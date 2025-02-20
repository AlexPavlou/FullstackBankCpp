#include <iostream> 
#include <string>
#include "crow_all.h"
#include "dotenv.h"
#include "jwt-cpp/jwt.h"
#include <sstream>
#include <iomanip>
#include <sw/redis++/redis++.h>
#include <ctime>
#include <sodium.h>
#include <curl/curl.h>
#include <limits> 
#include <pqxx/pqxx>
#include <random>
#include <memory>
#include <chrono>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <fstream>
#include <ctime>
#include <iomanip>
#ifdef _WIN32
#include <conio.h>  // For Windows-specific _getch()
#else
#include <termios.h>  // For Linux/macOS-specific termios API
#include <unistd.h>
#endif

// Global Variable(s)
sw::redis::Redis* redis = nullptr;
int MAX_ACCOUNTS = 3;
std::string JWT_SECRET;
int RESET_TOKEN_EXPIRATION = 1800; // 30 minutes in seconds

struct Transaction {
	std::string type; // Type of the transaction, can be either 'Withdrawal', 'Deposit', 'Outgoing-Transfer' or 'Incoming-Transfer'
	double amount;
	double balanceAfter;
    int ctp_id; // This variable holds the ID of the 'counterpart', basically the ID of either the sender or recipient in the case of transfers
};

class Logger {
public:
    enum LogLevel {
        INFO,
        DEBUG,
        ERROR
    };

    // Constructor that optionally takes a filename to log to
    Logger(const std::string& logFile = "") : logToFile(!logFile.empty()), logFileName(logFile) {
        if (logToFile) {
            logFileStream.open(logFileName, std::ios::app); // Open file in append mode
            if (!logFileStream.is_open()) {
                std::cerr << "Failed to open log file: " << logFileName << std::endl;
                logToFile = false;
            }
        }
    }

    // Destructor ensures the log file stream is closed
    ~Logger() {
        if (logToFile && logFileStream.is_open()) {
            logFileStream.close();
        }
    }

    // Log message with specified log level
    void log(LogLevel level, const std::string& message) {
        std::string levelStr = logLevelToString(level);
        std::string logMessage = getCurrentTime() + " [" + levelStr + "] " + message;

        if (logToFile) {
            if (logFileStream.is_open()) {
                logFileStream << logMessage << std::endl;
            }
        }
    }

private:
    std::ofstream logFileStream;
    bool logToFile;
    std::string logFileName;

    // Convert log level to string
    std::string logLevelToString(LogLevel level) {
        switch (level) {
        case INFO: return "INFO";
        case DEBUG: return "DEBUG";
        case ERROR: return "ERROR";
        default: return "UNKNOWN";
        }
    }

    // Get the current timestamp as a string
    std::string getCurrentTime() {
        auto now = std::time(nullptr);
        std::tm* localTime = std::localtime(&now);
        std::ostringstream timeStream;
        timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
        return timeStream.str();
    }
};

/* High-Level logging functions to log Debug and Error messages to the db.log file */
void logDebug(const std::string srt){
        Logger logger("db.log");
        logger.log(Logger::DEBUG, srt);
}

void logError(std::string_view before_str = "", std::string_view errMsg = ""){
        Logger logger("db.log");
        std::stringstream errorMsg;
        errorMsg << before_str << errMsg;
        logger.log(Logger::ERROR, errorMsg.str());
}

size_t payload_source(void* ptr, size_t size, size_t nmemb, void* userp) {
    const char* data = static_cast<const char*>(userp);
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    return len;
}

void saveTransaction(pqxx::connection& db, const std::string& username, const Transaction& trans, const int& account_id) {
    double amount = trans.amount;
    std::ostringstream stream;
    std::string type = trans.type;
    stream << ", Amount: " << std::fixed << std::setprecision(2) << trans.amount 
           << " €, Balance After: " << std::fixed << std::setprecision(2) << trans.balanceAfter << " €";

    if (trans.type == "Outgoing-Transfer") {
        stream << ", To: " << trans.ctp_id;
    } else if (trans.type == "Incoming-Transfer") {
        stream << ", From: " << trans.ctp_id;
    }

    std::string transaction_details = stream.str();

    // SQL query for inserting the transaction into the database
    const std::string insert_sql = 
        "INSERT INTO transactions (type, trans, account_id, amount) "
        "VALUES ($1, $2, $3, $4);";

    try {
        pqxx::work txn(db);

        txn.exec_params(insert_sql, type, transaction_details, account_id, amount);

        txn.commit();
    } catch (const std::exception& e) {
        logError("Error inserting transaction into database: ", e.what());
    }
}

std::string hashPassword(const std::string& password) {
    // Define a buffer to hold the hashed password (it's a fixed size in libsodium)
    char hashedPassword[crypto_pwhash_STRBYTES];

    // Hash the password using libsodium's password hashing function
    if (crypto_pwhash_str(hashedPassword, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("Password hashing failed");
    }

    // Return the hashed password as a std::string
    return std::string(hashedPassword);
}

bool initialize_sodium() {
    if (sodium_init() == -1) {
        logError("libsodium initialization failed!", "");
        return false;
    }
    return true;
}

class Account {
	private:
        pqxx::connection db;
		std::string username;
		double balance;
        int max_daily_trans;
        int customer_id;
        int ID;
	public:
		Account(std::string user, double user_balance, double trans_limit, int user_id, int id): username(user), balance(user_balance), max_daily_trans(trans_limit), customer_id(user_id), ID(id) {}
        std::string getUsername() const {
            return username;
        }
        void updateUsername(std::string new_username) {
            username = new_username;
        }
		double getBalance() const {
			return balance;
		}
        void updateBalance(double new_balance) {
            balance = new_balance;
        }
        int getID() {
            return ID;
        }
        int getCustomerID() {
            return customer_id;
        }
        double getTransLimit() const {
            return max_daily_trans;
        }
        void setTransLimit(double trans_limit) {
            max_daily_trans = trans_limit;
        }
};

double calculateDailyTrans(pqxx::connection& db, std::shared_ptr<Account> acc) {
    double total_trans = 0.0;

    // SQL query to calculate the sum of today's withdrawals and outgoing transfers
    const std::string select_transactions_sql =
        "SELECT COALESCE(SUM(amount), 0) FROM transactions "
        "WHERE account_id = $1 "
        "AND date(Date) = CURRENT_DATE "
        "AND (type = 'Withdrawal' OR type = 'Outgoing-Transfer');";

    try {
        pqxx::work txn(db);
        pqxx::result res = txn.exec_params(select_transactions_sql, acc->getID());

        if (!res.empty()) {
            total_trans = res[0][0].as<double>();
        } else {
            logError("Error executing statement in calculateDailyTrans(): No result.");
        }

        txn.commit();

    } catch (const std::exception& e) {
        logError("Error in calculateDailyTrans(): ", e.what());
        return -1.0;  // Return an error value
    }

    logDebug("Daily transactions spent: " + std::to_string(total_trans));
    return total_trans;
}

bool checkAccountIdUnique(pqxx::connection& db, int account_id) {
    try {
        pqxx::work txn(db);  // Start a transaction
        std::string sql = "SELECT COUNT(*) FROM accounts WHERE account_id = " + txn.quote(account_id) + ";";
        
        pqxx::result result = txn.exec(sql);  // Execute the query
        txn.commit();  // Commit the transaction

        // Check the result
        bool isUnique = result[0][0].as<int>() == 0;  // If count is 0, the account_id is unique
        return isUnique;
    } catch (const std::exception& e) {
        logError("Failed to execute query in checkAccountIdUnique(): ", e.what());
        return false;
    }
}

int generateAccountID(pqxx::connection& db) {
    int account_id;
    bool isUnique = false;
    
    while (!isUnique) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(100000000, 999999999);  // Range for 9-digit number
        account_id = dis(gen);
        isUnique = checkAccountIdUnique(db, account_id);
    }

    return account_id;
}

void send_email(const std::string& to, const std::string& subject, const std::string& message) {
    CURL* curl = curl_easy_init();
    struct curl_slist* recipients = nullptr;

    if (curl) {
        std::string username = dotenv::env["EMAIL_USERNAME"];
        curl_easy_setopt(curl, CURLOPT_URL, dotenv::env["SMTP_URL"].c_str());
        curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, dotenv::env["EMAIL_APP_PASSWORD"].c_str());
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, ("<" + username + ">").c_str());
        recipients = curl_slist_append(recipients, ("<" + to + ">").c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        std::string email_data = "To: " + to + "\r\n"
                                 "From: " + username + "\r\n"
                                 "Subject: " + subject + "\r\n"
                                 "\r\n" +
                                 message + "\r\n";

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, email_data.c_str());
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }
}

bool find_user(pqxx::connection& db, const std::string& username, std::string& password_hash) {
    try {
        pqxx::work txn(db);
        std::string sql = "SELECT password FROM users WHERE username = $1";
        pqxx::result res = txn.exec_params(sql, username);

        if (!res.empty()) {
            // If the query was successful, retrieve the password hash
            password_hash = res[0][0].as<std::string>();
            return true;
        } else {
            return false;
        }
    } catch (const std::exception& e) {
        logError("Error in function find_user(): ", e.what());
        return false;
    }
}

bool emailExists(pqxx::connection& db, const std::string& email) {
    try {
        pqxx::work txn(db);
        std::string sql = "SELECT COUNT(*) FROM users WHERE email = $1";
        pqxx::result res = txn.exec_params(sql, email);

        if (!res.empty()) {
            int count = res[0][0].as<int>();
            return count==1;
        } else {
            return false;
        }
    } catch (const std::exception& e) {
        logError("Error in function emailExists(): ", e.what());
        return false;
    }
}

bool userExists(pqxx::connection& db, const std::string& username, std::string& email) {
    try {
        pqxx::work txn(db);
        std::string sql = "SELECT COUNT(*) FROM users WHERE username = $1";
        pqxx::result res= txn.exec_params(sql, username);
    
        if (!res.empty()) {
            int count = res[0][0].as<int>();
            return count==1;
        } else { 
            return false;
        }
    } catch (const std::exception& e) {
        logError("Error in function userExists(): ", e.what());
        return false;
    }
}

bool hash_password(const std::string& password, std::string& hashed_password) {
    const size_t password_len = password.size();
    const size_t hashed_len = crypto_pwhash_STRBYTES;

    // Allocate memory for the hashed password
    hashed_password.resize(hashed_len);

    // Perform password hashing with a high work factor
    if (crypto_pwhash_str(&hashed_password[0], password.c_str(), password_len,
                          crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
        logError("In function hash_password(): Error hashing the password", "");
        return false;
    }

    return true;
}

bool insertUser(pqxx::connection& db, const std::string& username, const std::string& password, std::string& email, bool& two_fa) {
    if (username.empty()) {
        logError("In function insertUser(): Username cannot be empty!", "");
        return false;
    }

    // Hash the password before storing it
    std::string hashed_password;
    if (!hash_password(password, hashed_password)) {
        return false;
    }

    try {
        pqxx::work txn(db);  // Start a new transaction

        // SQL query to insert a new user
        const std::string sql = "INSERT INTO users (username, password, email, two_fa_enabled) VALUES ($1,$2,$3,$4)";

        txn.exec_params(sql, username, hashed_password, email, two_fa ? true : false);

        // Commit the transaction
        txn.commit();

        return true;
    } catch (const std::exception& e) {
        logError("Error inserting user in function insertUser(): ", e.what());
        return false;
    }
}

bool verify_password(const std::string& password, const std::string& hashed_password) {
    // Verify the entered password with the stored hashed password
    return crypto_pwhash_str_verify(hashed_password.c_str(), password.c_str(), password.size()) == 0;
}

// Function to check credentials
bool verifyLoginCredentials(pqxx::connection& db, const std::string& username, const std::string& password) {
    std::string pass_hash;
    if (find_user(db, username, pass_hash)) {
        if (verify_password(password, pass_hash)) {
            return true;
        }
    }
    return false;
}

std::string generateRandomJTI() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    return std::to_string(dist(gen));
}

std::string generateJWT(int user_id, const std::string& secret_key) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::minutes(15);

    auto token = jwt::create()
        .set_type("JWS")
        .set_issuer("auth0")
        .set_payload_claim("user_id", jwt::claim(std::to_string(user_id)))
        .set_payload_claim("exp", jwt::claim(std::to_string(std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count()))) // Convert to string
        .set_payload_claim("jti", jwt::claim(generateRandomJTI())) // Unique token ID
        .sign(jwt::algorithm::hs256{secret_key});

    return token;
}

bool validateJWT(const std::string& token, const std::string& secret_key) {
    auto decoded_token = jwt::decode(token);

    auto verifier = jwt::verify()
        .with_issuer("app_auth")
        .allow_algorithm(jwt::algorithm::hs256{secret_key});

    try {
        verifier.verify(decoded_token);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Token verification failed: " << e.what() << std::endl;
        return false;
    }
}

int getUserIdByUsername(pqxx::connection& db, const std::string username) {
    try {
        pqxx::work txn(db);
        std::string sql = "SELECT user_id FROM users WHERE username = $1";
        pqxx::result res = txn.exec_params(sql, username);

        if (!res.empty()) {
            return res[0][0].as<int>();
        }
    } catch (const std::exception& e) {
        logError("Error in function getUserIdByUsername(): ", e.what());
        return -1;
    }
    return -1;
}


std::string generateRandomString(size_t length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> dist(0, charset.size() - 1);
    
    std::string result;
    for (size_t i = 0; i < length; ++i) {
        result += charset[dist(generator)];
    }
    
    return result;
}

bool isTokenBlacklisted(const std::string& jti) {
    return redis->exists(jti) > 0;
}

std::optional<jwt::decoded_jwt<jwt::traits::kazuho_picojson>> parseJWT(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{JWT_SECRET})
            .with_issuer("app_auth");
        verifier.verify(decoded);  // Verify signature
        return decoded;  // Return decoded JWT if valid
    } catch (const std::exception& e) {
        return std::nullopt;  // Return nullopt if invalid or error occurs
    }
}

bool isValidToken(const crow::request& req, int* user_id = nullptr) {
    std::string authHeader = req.get_header_value("Authorization");
    if (authHeader.empty() || authHeader.substr(0, 7) != "Bearer ") {
        return false; // Missing or malformed token
    }

    std::string token = authHeader.substr(7);  // Extract token part

    // Parse and verify the JWT
    auto decoded = parseJWT(token);
    if (!decoded) {
        return false; // Invalid token
    }

    // Check if the token is blacklisted
    std::string jti = decoded->get_payload_claim("jti").as_string();
    if (isTokenBlacklisted(jti)) {
        return false; // Token revoked
    }

    if (user_id) {
        *user_id = decoded->get_payload_claim("user_id").to_json().get<int>();
    }

    return true; // Valid token
}

bool updateAccountBalanceInDB(pqxx::connection& db, double balance, int account_id) {
    try {
        pqxx::work txn(db);  // Start a transaction

        // Prepare the SQL query
        std::string updateSQL = "UPDATE accounts SET account_balance = $1 WHERE account_id = $2";

        // Execute the update statement
        txn.exec_params(updateSQL, balance, account_id);

        txn.commit();  // Commit the transaction

        return true;
    } catch (const std::exception& e) {
        logError("Failed to update account balance in DB in function updateAccountBalanceInDB: ", e.what());
        return false;  // Return false if an exception occurred
    }
}

bool deposit(pqxx::connection& db, double amount, bool showMessage, std::shared_ptr<Account> sender, std::shared_ptr<Account> recipient = nullptr) {
    if (amount <= 0) {
        std::cout << " !Deposit amount negative or invalid.\n";
        return false;
    }

    double temp_balance;
    std::string name;
    int account_id;

    if (recipient == nullptr) {
        logDebug("recipient is nullptr");
        // Deposit to sender's own account
        temp_balance = sender->getBalance() + amount;
        name = sender->getUsername();
        account_id = sender->getID();  // Unique account ID from sender
        if (updateAccountBalanceInDB(db, temp_balance, account_id)) {
            sender->updateBalance(temp_balance);
        } else {
            std::cout << " !Error updating balance in database.\n";
            return false;
        }
    } else {
        // Deposit to recipient's account
        temp_balance = recipient->getBalance() + amount;
        name = recipient->getUsername();
        account_id = recipient->getID();  // Unique account ID from recipient
        if (updateAccountBalanceInDB(db, temp_balance, account_id)) {
            recipient->updateBalance(temp_balance);
        } else {
            std::cout << " !Error updating recipient's balance in database.\n";
            return false;
        }
    }

    if (showMessage) {
        std::cout << " Successfully deposited " << amount << "€ to account: " << name << std::endl;
        // Log the transaction
        Transaction deposit = {"Deposit", amount, temp_balance};
        saveTransaction(db, name, deposit, sender->getID());
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Discard incorrect input
    return true;
}

bool withdraw(pqxx::connection& db, double amount, bool showMessage, std::shared_ptr<Account> account) {
    if (account == nullptr) {
        logError("Invalid account pointer in function withdraw(): ", "");
        return false;
    }

    double balance = account->getBalance();

    // Check for valid amount
    if (amount <= 0 || balance < amount) {
        std::cout << " !Insufficient funds or invalid amount. Withdrawal aborted.\n";
        return false;
    }

    double trans_limit = account->getTransLimit();
    int account_id = account->getID();  // Unique account_id

    if (trans_limit > 0.0) {
        double trans_spent = calculateDailyTrans(db, account);  // Calculate total spent today

        // Ensure the withdrawal does not exceed the daily transaction limit
        int diff = trans_limit - trans_spent;
        if ( amount > diff ) {
            /*std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear any extra input left in buffer
            if ( diff != 0.0 ) {
                std::cout << " !You have set a daily transaction limit of " << trans_limit << " €. You can only spend " << diff << " €.\n";
            } else {
                std::cout << " !You have set a daily transaction limit of " << trans_limit << " €.\n";
            }*/
            return false;  // Block the transaction if the limit would be exceeded
        }
    }

    // Proceed with the withdrawal if no limit is exceeded
    double temp_balance = balance - amount;  // New balance after withdrawal

    // Update the balance in the database and the account object
    if (updateAccountBalanceInDB(db, temp_balance, account_id)) {
        account->updateBalance(temp_balance);  // Update in-memory balance
    } else {
        std::cout << " !Error updating balance in database.\n";
        return false;
    }

    // Log the transaction if required
    if (showMessage) {
        std::cout << " Successfully withdrew " << amount << " € from account: " << account->getUsername() << std::endl;
        Transaction withdrawal = {"Withdrawal", amount, temp_balance};
        saveTransaction(db, account->getUsername(), withdrawal, account->getID());
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Discard incorrect input
    return true;
}

bool transfer(pqxx::connection& db, double amount, std::shared_ptr<Account> recipient, std::shared_ptr<Account> sender) {
    if (amount <= 0) {
        std::cout << " !Transfer amount must be greater than zero.\n";
        return false;
    }

    // First withdraw from sender's account
    if (!withdraw(db, amount, false, sender)) {
        std::cout << " !Transfer failed due to withdrawal issue.\n";
        return false;
    }

    // Now deposit into recipient's account
    deposit(db, amount, false, sender, recipient);

    // Log the transactions only if both actions are successful
    Transaction OutgoingTransferTransaction = {"Outgoing-Transfer", amount, sender->getBalance(), recipient->getID()};
    saveTransaction(db, sender->getUsername(), OutgoingTransferTransaction, sender->getID());

    Transaction IncomingTransferTransaction = {"Incoming-Transfer", amount, recipient->getBalance(), sender->getID()};
    saveTransaction(db, recipient->getUsername(), IncomingTransferTransaction, recipient->getID());
    return true;
}

std::shared_ptr<Account> lookupRecipient(pqxx::connection& db, const int& recipient_id) {
    try {
        pqxx::work txn(db);  // Start a transaction
        std::string query = "SELECT username, account_balance, customer_id FROM accounts WHERE account_id = " + txn.quote(recipient_id) + ";";
        
        pqxx::result result = txn.exec(query);  // Execute the query
        txn.commit();  // Commit the transaction

        if (result.empty()) {
            return nullptr;  // No result found, return nullptr
        }

        // Extract the values from the result
        std::string account_username = result[0][0].as<std::string>();
        double account_balance = result[0][1].as<double>();
        int customer_id = result[0][2].as<int>();

        // Create and return the Account object
        return std::make_shared<Account>(account_username, account_balance, false, customer_id, recipient_id);
    } catch (const std::exception& e) {
        logError("Error in lookupRecipient: ", e.what());
        return nullptr;  // Return nullptr in case of an error
    }
}

void setupRoutes(crow::SimpleApp& app, pqxx::connection& db) {
    // Login route
    CROW_ROUTE(app, "/login").methods("POST"_method)([&db](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("username") || !body.has("password")) {
            return crow::response(400, "Invalid JSON structure");
        }

        std::string username = body["username"].s();
        std::string password = body["password"].s();

        // Verify credentials
        if (verifyLoginCredentials(db, username, password)) {
            int user_id = getUserIdByUsername(db, username);
            if (user_id==0) {
                return crow::response(500, "Internal Server Error: Could not retrieve user id.");
            }

            std::string token = generateJWT(user_id, JWT_SECRET);

            // Return success with the token
            return crow::response(200, crow::json::wvalue{{"message", "Login successful"}, {"token", token}}.dump());
        } else {
            return crow::response(401, "Unauthorized");
        }
    });

    // Signup route
    CROW_ROUTE(app, "/signup").methods("POST"_method)([&db](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("username") || !body.has("password") || !body.has("e-mail")) {
            return crow::response(400, "Invalid JSON structure.");
        }

        std::string username = body["username"].s();
        std::string password = body["password"].s();
        std::string email = body["email"].s();
        bool two_fa = body.has("two_fa") ? body["two_fa"].b() : false;

        if (userExists(db, username, email)) {
            return crow::response(409, "Conflict: User already exists.");
        }

        if (!insertUser(db, username, password, email, two_fa)) {
            return crow::response(500, "Internal Server Error: Could not create user.");
        }

        int user_id = getUserIdByUsername(db, username);
        std::string token = generateJWT(user_id, JWT_SECRET);

        return crow::response(201, crow::json::wvalue{{"message", "User registered & logged in successfully"}, {"token", token}}.dump());
    });
    /*CROW_ROUTE(app, "/transactions").methods("POST"_method)([&db](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if(!body || !body.has("account_id")) {
            return crow::response(400, "Invalid JSON structure");
        }
        if(!isValidToken(req)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }
        
        std::string account_id = body["account_id"].s();
        pqxx::work txn(db);
        pqxx::result r = txn.exec_params("SELECT account_id FROM accounts WHERE account_id = $1", account_id);
        if(r.empty()) {
            return crow::response(404, "Account not found");
        }
        
        const std::string select_transactions_sql =
            "SELECT trans, type, date FROM transactions WHERE account_id = $1 ORDER BY id DESC;";
        pqxx::result transactions_result = txn.exec_params(select_transactions_sql, account_id);
        if(transactions_result.empty()) {
            return crow::response(404, "No transactions found for this account");
        }
        
        // Construct a JSON array for transactions.
        crow::json::wvalue transactions_array(crow::json::type::List);
        for(const auto& row : transactions_result) {
            crow::json::wvalue transaction;
            transaction["trans"] = std::string(row["trans"].c_str());
            transaction["type"] = std::string(row["type"].c_str());
            transaction["date"] = std::string(row["date"].c_str());
            transactions_array.push_back(std::move(transaction));
        }
        
        crow::json::wvalue result;
        result["transactions"] = std::move(transactions_array);
        
        crow::response resp(200, result.dump());
        resp.add_header("Content-Type", "application/json");
        return resp;
    });
    CROW_ROUTE(app, "/accounts").methods("GET"_method)([&db](const crow::request& req) {
        // Extract token from the Authorization header.
        std::string authHeader = req.get_header_value("Authorization");
        if(authHeader.size() < 7) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }
        std::string token = authHeader.substr(7);
        
        int user_id{};
        if(!isValidToken(req, &user_id)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }
        
        pqxx::work txn(db);
        pqxx::result r = txn.exec_params(
            "SELECT account_id, username, account_balance, trans_limit, created_at "
            "FROM accounts WHERE customer_id = $1", user_id);
        if(r.empty()) {
            return crow::response(404, "No accounts found");
        }
        
        // Construct a JSON array using wvalue as a List.
        crow::json::wvalue accounts_array(crow::json::type::List);
        for(const auto& row : r) {
            crow::json::wvalue account;
            account["account_id"] = row["account_id"].as<int>();
            account["username"] = std::string(row["username"].c_str());
            account["account_balance"] = row["account_balance"].as<double>();
            account["trans_limit"] = row["trans_limit"].as<double>();
            account["created_at"] = std::string(row["created_at"].c_str());
            accounts_array.push_back(std::move(account));
        }
        
        // Insert the array into the result JSON object.
        crow::json::wvalue result;
        result["accounts"] = std::move(accounts_array);
        
        crow::response resp(200, result.dump());
        resp.add_header("Content-Type", "application/json");
        return resp;
    });*/
    CROW_ROUTE(app, "/logout").methods("POST"_method)([](const crow::request& req) {
        if (!isValidToken(req)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }

        // Extract the token and JTI from the request again
        std::string authHeader = req.get_header_value("Authorization");
        std::string token = authHeader.substr(7);  // Extract token part
        auto decoded = parseJWT(token);
        if (!decoded) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }

        std::string jti = decoded->get_payload_claim("jti").as_string();
        int exp = decoded->get_payload_claim("exp").to_json().get<int>();

        int ttl = exp - std::time(nullptr);
        if (ttl > 0) {
            try {
                redis->set(jti, "blacklisted", std::chrono::seconds(ttl));
            } catch (const sw::redis::Error& e) {
                logError("Error setting value in Redis: ", e.what());
                return crow::response(500, "Internal Server Error");
            }
        }
        return crow::response(200, "Logged out successfully");
    });
    CROW_ROUTE(app, "/transfer").methods("POST"_method)([&db](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("from_account_id") || !body.has("to_account_id") || !body.has("amount")) {
            return crow::response(400, "Invalid JSON structure");
        }

        if (!isValidToken(req)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }

        int from_account_id = body["from_account_id"].i();
        int to_account_id = body["to_account_id"].i();
        float amount = body["amount"].i();

        // Create a shared_ptr of Account
        std::shared_ptr<Account> sender = lookupRecipient(db, from_account_id);
        std::shared_ptr<Account> recipient = lookupRecipient(db, to_account_id);

        if (transfer(db, amount, recipient, sender)) {
            return crow::response(200, "transfer completed successfully");
        }
        return crow::response(404, "Sender not found");
    });
    CROW_ROUTE(app, "/user").methods("POST"_method)([&db](const crow::request& req) {
        int user_id{};

        // Validate the token
        if (!isValidToken(req, &user_id)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }
        pqxx::work txn(db);
        pqxx::result res = txn.exec_params("SELECT email, two_fa_enabled, username, created_at FROM accounts WHERE account_id = $1", user_id);

        if (res.empty()) {
            return crow::response(404, "User not found");
        }

        const auto& row = res[0];
        crow::json::wvalue response;

        response["email"] = row["email"].as<std::string>();
        response["two_fa_enabled"] = row["two_fa_enabled"].as<bool>();
        response["username"] = row["username"].as<std::string>();
        response["created_at"] = row["created_at"].as<std::string>();

        return crow::response{response};
    });
    CROW_ROUTE(app, "/reset-password-request").methods("POST"_method)([&db](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("e-mail")) {
            return crow::response(400, "Invalid JSON structure");
        }

        if (!isValidToken(req)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }

        std::string email = body["e-mail"].s();
        if (!emailExists(db, email)) {
            return crow::response(404, "E-mail not found");
        }

        std::string reset_token = generateRandomString(40);

        redis->set(reset_token, "reset_token", std::chrono::seconds(RESET_TOKEN_EXPIRATION));

        std::string email_body = "Hello Xx_Babis_xX,\n\nThis is your password reset link: http://localhost:8080/myapp/?reset-link=" + reset_token;

        send_email(email, "Xx_Babis_xX Password Reset Link", email_body);

        return crow::response(200, "Reset password link set successfully");
    });
    CROW_ROUTE(app, "/reset-password").methods("POST"_method)([&db](const crow::request& req) {
        int user_id;  
        auto body = crow::json::load(req.body);

        if (!isValidToken(req, &user_id)) {
            return crow::response(401, "Unauthorized: Invalid or missing token");
        }

        if (!body || !body.has("token") || !body.has("new_password")) {
            return crow::response(400, "Invalid request, token and new password are required");
        }

        std::string reset_token = body["token"].s();
        std::string new_password = body["new_password"].s();

        if (redis->exists(reset_token) == 0) {
            return crow::response(404, "Reset token was not found");
        }

        pqxx::work txn(db);
        std::string hashed_password;
        hash_password(new_password, hashed_password);

        txn.exec_params("UPDATE accounts SET password = $1 WHERE user_id = $2", hashed_password, user_id);
        txn.commit();

        redis->del(reset_token);

        return crow::response(200, "Password successfully changed");
    });
}

int getCustomerIDByUsername(pqxx::connection& db, const std::string& username) {
    try {
        pqxx::work txn(db);  // Start a transaction
        std::string query = "SELECT customer_id FROM users WHERE username = " + txn.quote(username) + ";";
        
        pqxx::result result = txn.exec(query);  // Execute the query
        txn.commit();  // Commit the transaction

        if (result.empty()) {
            std::cout << " !User not found.\n";
            return -1;
        }

        // Return the customer_id
        return result[0][0].as<int>();
    } catch (const std::exception& e) {
        logError("Failed to execute query in getCustomerIDByUsername: ", e.what());
        return -1;
    }
}

// Function to initialize the database and create the table (if they don't exist)
int createTables(pqxx::connection& db_conn) {
    try {
        pqxx::work txn(db_conn);  // Transaction object

        // Create 'users' table
        txn.exec(R"(
            CREATE TABLE IF NOT EXISTS users (
                customer_id SERIAL PRIMARY KEY,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                two_fa_enabled BOOLEAN DEFAULT FALSE,
                username VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        )");

        // Create 'accounts' table
        txn.exec(R"(
            CREATE TABLE IF NOT EXISTS accounts (
                account_id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                account_balance REAL NOT NULL,
                trans_limit REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES users(customer_id) ON DELETE CASCADE
            );
        )");

        // Create 'transactions' table
        txn.exec(R"(
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                trans TEXT NOT NULL,
                account_id INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        )");

        // Create index on account_id in accounts table
        txn.exec(R"(
            CREATE INDEX IF NOT EXISTS idx_account_id ON accounts(account_id);
        )");

        txn.commit();
        std::cout << "Tables created or already exist." << std::endl;
        return 0;
    } catch (const pqxx::sql_error& e) {
        std::cerr << "Error creating tables: " << e.what() << std::endl;
        return 1;
    }
}

pqxx::connection* initializeDatabase() {
    if (sodium_init() == -1) {
        logError("libsodium initialization failed! (function: int main())","");
        return nullptr;
    }

    std::string db_name = dotenv::env["DB_NAME"];
    std::string db_user = dotenv::env["DB_USER"];
    std::string db_pass = dotenv::env["DB_PASSWORD"];

    std::string db_conninfo = "dbname=" + db_name + " user=" + db_user + " password=" + db_pass; 
    pqxx::connection* conn = nullptr;

    try {
        conn = new pqxx::connection(db_conninfo);
        if (!conn->is_open()) {
            logError("Failed to open database", "");
            return nullptr;
        }

        // Create pgcrypto extension if it does not exists
        pqxx::work txn(*conn);
        txn.exec("CREATE EXTENSION IF NOT EXISTS pgcrypto;");
        txn.commit();

        if (createTables(*conn) != 0) {
            conn->close();
            delete conn;
            return nullptr;
        }

        return conn;
    } catch (const std::exception& e) {
        logError("Error opening PostgreSQL database: " + std::string(e.what()), "");
        return nullptr;
    }
}

int main () {
    dotenv::env.load_dotenv();
    crow::SimpleApp app;
    std::string addr = "tcp://" + dotenv::env["ADDRESS"];
    redis = new sw::redis::Redis(addr);

    pqxx::connection* db = initializeDatabase();
    if (db == nullptr) {
        std::cerr << "Failed to initialize the PostgreSQL database" << std::endl;
        return 1;
    }
    setupRoutes(app, *db);
    app.port(8080).multithreaded().run();
    delete db;
    delete redis;
    return 0;
}
