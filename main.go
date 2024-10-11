package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "time"
	"github.com/joho/godotenv"
	"os"
)

type TokenResponse struct {
    AccessToken string `json:"access_token"`
}

type GraphAPIResponse struct {
    Value []map[string]interface{} `json:"value"`
}

// Extend AuditLog struct with more fields
type AuditLog struct {
    Level            string `json:"level"`
    Job              string `json:"job"`
    Log              string `json:"log"`
    ActivityDateTime string `json:"activityDateTime"`
    Category         string `json:"category"`
    CorrelationID    string `json:"correlationId"`
    Result           string `json:"result"`
    UserPrincipal    string `json:"userPrincipalName"` // New field for user principal
    ClientApp        string `json:"clientAppUsed"`     // New field for client app used
    IPAddress        string `json:"ipAddress"`         // New field for IP address
}

// Function to get access token from Microsoft Graph API
func getAccessToken(tenantID, clientID, clientSecret string) string {
    tokenURL := "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token"
    data := "client_id=" + clientID + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=" + clientSecret + "&grant_type=client_credentials"

    req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer([]byte(data)))
    if err != nil {
        log.Fatalf("Error creating token request: %v", err)
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("Error getting token: %v", err)
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    var tokenResponse TokenResponse
    json.Unmarshal(body, &tokenResponse)

    return tokenResponse.AccessToken
}

// Function to retrieve logs from a given Microsoft Graph API endpoint
func getLogsFromEndpoint(accessToken, apiURL string) []map[string]interface{} {
    req, _ := http.NewRequest("GET", apiURL, nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("Error fetching logs: %v", err)
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)

    var graphResponse GraphAPIResponse
    err = json.Unmarshal(body, &graphResponse)
    if err != nil {
        log.Fatalf("Error unmarshalling logs: %v", err)
    }

    return graphResponse.Value
}

// Function to map audit logs for consent approvals to AuditLog struct
func mapToConsentLogs(rawLogs []map[string]interface{}) []AuditLog {
    var consentLogs []AuditLog
    for _, logEntry := range rawLogs {
        if logEntry["activityDisplayName"] == "Consent to application" {
            consentLogs = append(consentLogs, AuditLog{
                Level:            "info",
                Job:              "user_consent",
                Log:              fmt.Sprintf("User %s approved consent for %s", logEntry["initiatedBy"].(map[string]interface{})["user"].(map[string]interface{})["userPrincipalName"], logEntry["targetResources"].([]interface{})[0].(map[string]interface{})["displayName"]),
                ActivityDateTime: logEntry["activityDateTime"].(string),
                Category:         "Consent",
                CorrelationID:    logEntry["correlationId"].(string),
                Result:           logEntry["result"].(string),
                UserPrincipal:    logEntry["initiatedBy"].(map[string]interface{})["user"].(map[string]interface{})["userPrincipalName"].(string),
                ClientApp:        "N/A", // Not relevant for consent logs
                IPAddress:        "N/A", // Not relevant for consent logs
            })
        }
    }
    return consentLogs
}

// Function to map sign-in logs to AuditLog struct
func mapToSignInLogs(rawLogs []map[string]interface{}) []AuditLog {
    var signInLogs []AuditLog
    for _, logEntry := range rawLogs {
        signInLogs = append(signInLogs, AuditLog{
            Level:            "info",
            Job:              "user_signin",
            Log:              fmt.Sprintf("User %s signed in using %s from IP %s", logEntry["userPrincipalName"], logEntry["clientAppUsed"], logEntry["ipAddress"]),
            ActivityDateTime: logEntry["createdDateTime"].(string),
            Category:         "SignIn",
            CorrelationID:    logEntry["correlationId"].(string),
            Result:           logEntry["status"].(map[string]interface{})["value"].(string),
            UserPrincipal:    logEntry["userPrincipalName"].(string),
            ClientApp:        logEntry["clientAppUsed"].(string),
            IPAddress:        logEntry["ipAddress"].(string),
        })
    }
    return signInLogs
}

// Function to map raw logs to AuditLog struct
func mapToAuditLogs(rawLogs []map[string]interface{}, jobName string) []AuditLog {
    var auditLogs []AuditLog
    for _, logEntry := range rawLogs {
        auditLogs = append(auditLogs, AuditLog{
            Level:            "info", // Default log level, adjust as necessary
            Job:              jobName,
            Log:              fmt.Sprintf("Action: %s | Result: %s", logEntry["activityDisplayName"], logEntry["result"]),
            ActivityDateTime: logEntry["activityDateTime"].(string),
            Category:         logEntry["category"].(string),
            CorrelationID:    logEntry["correlationId"].(string),
            Result:           logEntry["result"].(string),
            UserPrincipal:    "N/A", // Only relevant for certain logs
            ClientApp:        "N/A", // Only relevant for certain logs
            IPAddress:        "N/A", // Only relevant for certain logs
        })
    }
    return auditLogs
}

// Function to push logs to OpenObserve
func pushLogsToOpenObserve(logs []AuditLog, orgID, streamName, openObserveHost, base64Creds string) {
    jsonData, err := json.Marshal(logs)
    if err != nil {
        log.Fatalf("Error marshalling logs: %v", err)
    }

    // Define OpenObserve endpoint and credentials
    openObserveURL := fmt.Sprintf("http://%s/api/%s/%s/_json", openObserveHost, orgID, streamName)
    req, err := http.NewRequest("POST", openObserveURL, bytes.NewBuffer(jsonData))
    if err != nil {
        log.Fatalf("Error creating request: %v", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Basic "+base64Creds)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalf("Error sending logs to OpenObserve: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("Error reading response body: %v", err)
    }

    fmt.Printf("Response Status: %s\n", resp.Status)
    fmt.Printf("Response Body: %s\n", string(body))

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        fmt.Println("Logs successfully pushed to OpenObserve")
    } else {
        fmt.Printf("Failed to push logs: %s\n", string(body))
    }
}

// Function to run the connector logic continuously
func runConnector(tenantID, clientID, clientSecret, orgID, streamName, openObserveHost, base64Creds string) {
    for {
        fmt.Println("Fetching logs from Microsoft Graph API...")

        // Get the access token from Microsoft Graph API
        accessToken := getAccessToken(tenantID, clientID, clientSecret)

        // Fetch audit logs
        auditLogs := getLogsFromEndpoint(accessToken, "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits")
        mappedAuditLogs := mapToAuditLogs(auditLogs, "microsoft_audit")

        // Fetch directory logs
        directoryLogs := getLogsFromEndpoint(accessToken, "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits")
        mappedDirectoryLogs := mapToAuditLogs(directoryLogs, "microsoft_directory")

        // Fetch sign-in activity logs (existing logic)
        activityLogs := getLogsFromEndpoint(accessToken, "https://graph.microsoft.com/v1.0/auditLogs/signIns")
        mappedActivityLogs := mapToAuditLogs(activityLogs, "microsoft_signin")

        // --- New logic for user sign-ins ---
        // Fetch and map user sign-ins
        signInLogs := getLogsFromEndpoint(accessToken, "https://graph.microsoft.com/v1.0/auditLogs/signIns")
        mappedSignInLogs := mapToSignInLogs(signInLogs)

        // --- New logic for consent approvals ---
        // Fetch and map user consent approvals
        consentLogs := mapToConsentLogs(auditLogs) // Consent approvals come from audit logs

        // Combine all logs into a single array
        allLogs := append(mappedAuditLogs, mappedDirectoryLogs...)
        allLogs = append(allLogs, mappedActivityLogs...)
        allLogs = append(allLogs, mappedSignInLogs...)
        allLogs = append(allLogs, consentLogs...)

        // Push all logs to OpenObserve
        pushLogsToOpenObserve(allLogs, orgID, streamName, openObserveHost, base64Creds)

        // Wait for 5 seconds before the next fetch
        fmt.Println("Waiting for 5 seconds...")
        time.Sleep(5 * time.Second)
    }
}

// Main entry point
func main() {
	err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file")
    }
    tenantID := os.Getenv("TENANT_ID")
    clientID := os.Getenv("CLIENT_ID")
    clientSecret := os.Getenv("CLIENT_SECRET")
    orgID := os.Getenv("ORG_ID")
    streamName := os.Getenv("STREAM_NAME")
    openObserveHost := os.Getenv("OPEN_OBSERVE_HOST")
    base64Creds := os.Getenv("BASE64_CREDS")

    // Validate that environment variables are set
    if tenantID == "" || clientID == "" || clientSecret == "" || orgID == "" || streamName == "" || openObserveHost == "" || base64Creds == "" {
        log.Fatal("One or more required environment variables are missing.")
    }

    // Run the connector continuously
    runConnector(tenantID, clientID, clientSecret, orgID, streamName, openObserveHost, base64Creds)
}

