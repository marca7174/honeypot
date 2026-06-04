/**
 * risk_engine.cpp — Digital Mirror v2 — Enhanced C++ OOP Risk Engine
 *
 * Additions over v1:
 *  - ThreatLevel enum  : NONE / LOW / MEDIUM / HIGH / CRITICAL
 *  - Identity enum     : UNKNOWN / EMPLOYEE / THREAT
 *  - Persistent log file (risk_engine.log) written from C++
 *  - getRoleStr() / getThreatLevelStr() helpers for JSON export
 *  - OTP tracking fields (last_otp_attempt, otp_failures)
 *
 * Compile:
 *   Linux/macOS : g++ -O2 -shared -fPIC -std=c++17 -o risk_engine.so risk_engine.cpp
 *   Windows     : g++ -O2 -shared -std=c++17 -o risk_engine.dll risk_engine.cpp
 */

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <ctime>
#include <cstring>
#include <sstream>
#include <iomanip>
// #include <mutex>  // Disabled for older MinGW compatibility

// ─────────────────────────────────────────────
//  Enums
// ─────────────────────────────────────────────

enum class Identity {
    UNKNOWN,
    EMPLOYEE,
    THREAT
};

enum class ThreatLevel {
    NONE     = 0,   // score   0-19   (clean / employee)
    LOW      = 1,   // score  20-49
    MEDIUM   = 2,   // score  50-79
    HIGH     = 3,   // score  80-99
    CRITICAL = 4    // score 100+     (banned)
};

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

static std::string timestamp() {
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

static ThreatLevel scoreToLevel(int score) {
    if (score >= 100) return ThreatLevel::CRITICAL;
    if (score >= 80)  return ThreatLevel::HIGH;
    if (score >= 50)  return ThreatLevel::MEDIUM;
    if (score >= 20)  return ThreatLevel::LOW;
    return ThreatLevel::NONE;
}

static const char* levelStr(ThreatLevel lvl) {
    switch (lvl) {
        case ThreatLevel::NONE:     return "NONE";
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
    }
    return "NONE";
}

static const char* identityStr(Identity id) {
    switch (id) {
        case Identity::EMPLOYEE: return "EMPLOYEE";
        case Identity::THREAT:   return "THREAT";
        default:                 return "UNKNOWN";
    }
}

// ─────────────────────────────────────────────
//  Logger — writes to disk
// ─────────────────────────────────────────────

class Logger {
private:
    std::ofstream file;
    // std::mutex    mtx;  // Disabled for older MinGW compatibility
    std::string   path;
public:
    explicit Logger(const std::string& logPath) : path(logPath) {
        file.open(logPath, std::ios::app);
    }
    ~Logger() { if (file.is_open()) file.close(); }

    void write(const std::string& level, const std::string& msg) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        std::string line = "[" + timestamp() + "] [" + level + "] " + msg;
        std::cout << line << "\n";
        if (file.is_open()) { file << line << "\n"; file.flush(); }
    }

    void info (const std::string& msg) { write("INFO",  msg); }
    void warn (const std::string& msg) { write("WARN",  msg); }
    void alert(const std::string& msg) { write("ALERT", msg); }
};

static Logger gLogger("logs/risk_engine.log");

// ─────────────────────────────────────────────
//  UserSession — OOP core object
// ─────────────────────────────────────────────

class UserSession {
private:
    std::string  ipAddress;
    int          riskScore;
    Identity     identity;
    ThreatLevel  threatLevel;
    int          failed2FAAttempts;
    int          otpFailures;
    time_t       banExpiry;
    time_t       firstSeen;
    time_t       lastSeen;
    std::string  lastAction;

    void recalcLevel() {
        threatLevel = scoreToLevel(riskScore);
    }

    void triggerBan() {
        banExpiry = time(nullptr) + 3600;
        identity  = Identity::THREAT;
        gLogger.alert("IP " + ipAddress + " BANNED for 1 hour — score: " +
                      std::to_string(riskScore) + " | Level: CRITICAL");
    }

public:
    UserSession()
        : ipAddress(""), riskScore(0), identity(Identity::UNKNOWN),
          threatLevel(ThreatLevel::NONE), failed2FAAttempts(0),
          otpFailures(0), banExpiry(0),
          firstSeen(time(nullptr)), lastSeen(time(nullptr)) {}

    explicit UserSession(const std::string& ip)
        : ipAddress(ip), riskScore(0), identity(Identity::UNKNOWN),
          threatLevel(ThreatLevel::NONE), failed2FAAttempts(0),
          otpFailures(0), banExpiry(0),
          firstSeen(time(nullptr)), lastSeen(time(nullptr)) {
        gLogger.info("New session: " + ip);
    }

    // ── Mutators ──────────────────────────────

    void addRiskPoints(int points, const std::string& reason) {
        lastSeen   = time(nullptr);
        lastAction = reason;
        riskScore += points;
        recalcLevel();
        gLogger.warn("IP " + ipAddress + " | " + reason +
                     " | +" + std::to_string(points) +
                     " pts -> score=" + std::to_string(riskScore) +
                     " [" + levelStr(threatLevel) + "]");
        if (riskScore >= 100 && banExpiry == 0) triggerBan();
    }

    void recordFailed2FA() {
        failed2FAAttempts++;
        otpFailures++;
        addRiskPoints(35, "FAILED_2FA");
    }

    void recordOTPFailure() {
        otpFailures++;
        addRiskPoints(10, "FAILED_OTP");
    }

    void markEmployee() {
        identity = Identity::EMPLOYEE;
        lastSeen = time(nullptr);
        gLogger.info("IP " + ipAddress + " identified as EMPLOYEE");
    }

    void markThreat(const std::string& reason) {
        identity = Identity::THREAT;
        lastSeen = time(nullptr);
        gLogger.alert("IP " + ipAddress + " explicitly marked as THREAT: " + reason);
    }

    // ── Accessors ─────────────────────────────

    int          getRiskScore()   const { return riskScore; }
    Identity     getIdentity()    const { return identity; }
    ThreatLevel  getThreatLevel() const { return threatLevel; }
    int          get2FAFails()    const { return failed2FAAttempts; }
    int          getOTPFails()    const { return otpFailures; }
    time_t       getBanExpiry()   const { return banExpiry; }
    time_t       getFirstSeen()   const { return firstSeen; }
    time_t       getLastSeen()    const { return lastSeen; }
    const std::string& getIP()    const { return ipAddress; }
    const std::string& getLastAction() const { return lastAction; }

    bool isBanned() const {
        if (banExpiry == 0) return false;
        return time(nullptr) < banExpiry;
    }

    // Serialise to a simple |-delimited string for the C API
    std::string toRecord() const {
        std::ostringstream ss;
        ss << ipAddress          << "|"
           << riskScore          << "|"
           << identityStr(identity) << "|"
           << levelStr(threatLevel) << "|"
           << (isBanned() ? "1" : "0") << "|"
           << banExpiry          << "|"
           << failed2FAAttempts  << "|"
           << otpFailures        << "|"
           << firstSeen          << "|"
           << lastSeen           << "|"
           << lastAction;
        return ss.str();
    }
};

// ─────────────────────────────────────────────
//  RiskEngine — Singleton
// ─────────────────────────────────────────────

class RiskEngine {
private:
    std::unordered_map<std::string, UserSession> activeSessions;
    // std::mutex mtx;  // Disabled for older MinGW compatibility

    RiskEngine() {
        gLogger.info("RiskEngine v2 Singleton initialised.");
    }

    UserSession& getOrCreate(const std::string& ip) {
        auto it = activeSessions.find(ip);
        if (it == activeSessions.end()) {
            activeSessions.emplace(ip, UserSession(ip));
        }
        return activeSessions.at(ip);
    }

public:
    RiskEngine(const RiskEngine&)            = delete;
    RiskEngine& operator=(const RiskEngine&) = delete;

    static RiskEngine& getInstance() {
        static RiskEngine instance;
        return instance;
    }

    // ── Core API ──────────────────────────────

    void trackAction(const std::string& ip, const std::string& action) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        UserSession& s = getOrCreate(ip);

        if      (action == "FAILED_LOGIN")           { s.addRiskPoints(15, action); s.markThreat(action); }
        else if (action == "ACCESS_SENSITIVE_DIR")   s.addRiskPoints(60, action);
        else if (action == "FAILED_2FA")             s.recordFailed2FA();
        else if (action == "FAILED_OTP")             s.recordOTPFailure();
        else if (action == "PORT_SCAN")              { s.addRiskPoints(40, action); s.markThreat(action); }
        else if (action == "SQL_INJECTION_ATTEMPT")  { s.addRiskPoints(80, action); s.markThreat(action); }
        else if (action == "XSS_ATTEMPT")            { s.addRiskPoints(70, action); s.markThreat(action); }
        else if (action == "BRUTE_FORCE")            { s.addRiskPoints(50, action); s.markThreat(action); }
        else                                         s.addRiskPoints(5, action);
    }

    void markEmployee(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        getOrCreate(ip).markEmployee();
    }

    bool checkBanStatus(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        auto it = activeSessions.find(ip);
        return (it != activeSessions.end()) ? it->second.isBanned() : false;
    }

    int getRiskScore(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        auto it = activeSessions.find(ip);
        return (it != activeSessions.end()) ? it->second.getRiskScore() : 0;
    }

    int getThreatLevel(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        auto it = activeSessions.find(ip);
        return (it != activeSessions.end()) ? (int)it->second.getThreatLevel() : 0;
    }

    // Returns pipe-delimited record for one IP
    std::string getRecord(const std::string& ip) {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        auto it = activeSessions.find(ip);
        return (it != activeSessions.end()) ? it->second.toRecord() : "";
    }

    // Returns newline-delimited list of all records
    std::string getAllRecords() {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        std::ostringstream ss;
        for (auto& kv : activeSessions) {
            ss << kv.second.toRecord() << "\n";
        }
        return ss.str();
    }

    void dumpSessions() {
        // std::lock_guard<std::mutex> lock(mtx);  // Disabled
        gLogger.info("=== Session Dump ===");
        for (auto& kv : activeSessions) {
            gLogger.info(kv.second.toRecord());
        }
    }
};

// ─────────────────────────────────────────────
//  C API — exposed to Python via ctypes
// ─────────────────────────────────────────────

extern "C" {

    void track_action(const char* ip, const char* action) {
        if (!ip || !action) return;
        RiskEngine::getInstance().trackAction(ip, action);
    }

    void mark_employee(const char* ip) {
        if (!ip) return;
        RiskEngine::getInstance().markEmployee(ip);
    }

    int is_banned(const char* ip) {
        if (!ip) return 0;
        return RiskEngine::getInstance().checkBanStatus(ip) ? 1 : 0;
    }

    int get_risk_score(const char* ip) {
        if (!ip) return 0;
        return RiskEngine::getInstance().getRiskScore(ip);
    }

    int get_threat_level(const char* ip) {
        if (!ip) return 0;
        return RiskEngine::getInstance().getThreatLevel(ip);
    }

    // Writes the record string into out_buf (caller allocates ≥1024 bytes)
    void get_record(const char* ip, char* out_buf, int buf_size) {
        if (!ip || !out_buf) return;
        std::string rec = RiskEngine::getInstance().getRecord(ip);
        strncpy(out_buf, rec.c_str(), buf_size - 1);
        out_buf[buf_size - 1] = '\0';
    }

    // Writes ALL records into out_buf (caller allocates ≥65536 bytes)
    void get_all_records(char* out_buf, int buf_size) {
        if (!out_buf) return;
        std::string all = RiskEngine::getInstance().getAllRecords();
        strncpy(out_buf, all.c_str(), buf_size - 1);
        out_buf[buf_size - 1] = '\0';
    }

    void dump_sessions() {
        RiskEngine::getInstance().dumpSessions();
    }

}  // extern "C"
