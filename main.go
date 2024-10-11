package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strconv"
    "time"
    "github.com/joho/godotenv"
)

type TokenResponse struct {
    AccessToken string `json:"access_token"`
}

type GraphAPIResponse struct {
    Value     []map[string]interface{} `json:"value"`
    DeltaLink string                   `json:"@odata.deltaLink"`
}

type AuditLog struct {
    Level            string `json:"level"`
    Job              string `json:"job"`
    Log              string `json:"log"`
    ActivityDateTime string `json:"activityDateTime"`
    Category         string `json:"category"`
    CorrelationID    string `json:"correlationId"`
    Result           string `json:"result"`
    UserPrincipal    string `json:"userPrincipalName"`
    ClientApp        string `json:"clientAppUsed"`
    IPAddress        string `json:"ipAddress"`
}

// Global variable to store delta link for future requests
var deltaLink string

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

// Function to retrieve logs using delta query
func getLogsFromEndpoint(accessToken, apiURL string) ([]map[string]interface{}, string, error) {
    if deltaLink != "" {
        apiURL = deltaLink // Use deltaLink if available
    }

    req, _ := http.NewRequest("GET", apiURL, nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, "", fmt.Errorf("Error fetching logs: %v", err)
    }
    defer resp.Body.Close()

    // Handle 429 throttling response
    if resp.StatusCode == 429 {
        retryAfter := resp.Header.Get("Retry-After")
        delay, err := strconv.Atoi(retryAfter)
        if err == nil {
            log.Printf("Throttled. Retrying after %d seconds...", delay)
            time.Sleep(time.Duration(delay) * time.Second)
        } else {
            log.Println("Throttled. Retrying after 60 seconds...")
            time.Sleep(60 * time.Second)
        }
        return nil, "", fmt.Errorf("Throttled: 429 Too Many Requests")
    }

    body, _ := ioutil.ReadAll(resp.Body)

    var graphResponse GraphAPIResponse
    err = json.Unmarshal(body, &graphResponse)
    if err != nil {
        return nil, "", fmt.Errorf("Error unmarshalling logs: %v", err)
    }

    return graphResponse.Value, graphResponse.DeltaLink, nil
}

// Function to map audit logs to the AuditLog struct
func mapToAuditLogs(rawLogs []map[string]interface{}, jobName string) []AuditLog {
    var auditLogs []AuditLog
    for _, logEntry := range rawLogs {
        auditLogs = append(auditLogs, AuditLog{
            Level:            "info",
            Job:              jobName,
            Log:              fmt.Sprintf("Action: %s | Result: %s", logEntry["activityDisplayName"], logEntry["result"]),
            ActivityDateTime: logEntry["activityDateTime"].(string),
            Category:         logEntry["category"].(string),
            CorrelationID:    logEntry["correlationId"].(string),
            Result:           logEntry["result"].(string),
            UserPrincipal:    "N/A",
            ClientApp:        "N/A",
            IPAddress:        "N/A",
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

// Run the connector logic continuously
func runConnector(tenantID, clientID, clientSecret, orgID, streamName, openObserveHost, base64Creds string) {
    for {
        fmt.Println("Fetching logs from Microsoft Graph API...")

        // Get access token from Microsoft Graph API
        accessToken := getAccessToken(tenantID, clientID, clientSecret)

        // Fetch audit logs using delta queries
        logs, newDeltaLink, err := getLogsFromEndpoint(accessToken, "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits")
        if err != nil {
            log.Printf("Error fetching logs: %v", err)
            continue
        }

        // Map the logs to our struct
        auditLogs := mapToAuditLogs(logs, "microsoft_audit")

        // Push logs to OpenObserve
        pushLogsToOpenObserve(auditLogs, orgID, streamName, openObserveHost, base64Creds)

        // Update the delta link for the next request
        if newDeltaLink != "" {
            deltaLink = newDeltaLink
        }

        // Wait for 5 seconds before the next fetch
        fmt.Println("Waiting for 5 seconds...")
        time.Sleep(5 * time.Second)
    }
}

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