package main

import (
    "bytes"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/big"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/consensys/gnark-crypto/ecc"
    starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
    "github.com/consensys/gnark-crypto/ecc/stark-curve/ecdsa"
    "github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
    "github.com/dontpanicdao/caigo"
    "github.com/dontpanicdao/caigo/types"
    "github.com/ethereum/go-ethereum/crypto"
)

// `GET /system/config`
func GetParadexConfig() (SystemConfigResponse, error) {
    systemConfigUrl := fmt.Sprintf("%s/system/config", PARADEX_HTTP_URL)
    response, err := http.Get(systemConfigUrl)
    if err != nil {
        return SystemConfigResponse{}, err
    }
    responseData, err := io.ReadAll(response.Body)
    if err != nil {
        return SystemConfigResponse{}, err
    }
    var config SystemConfigResponse
    err = json.Unmarshal(responseData, &config)
    if err != nil {
        return SystemConfigResponse{}, err
    }
    return config, nil
}

// Generate Ethereum public key from Ethereum private key
func GetEthereumAccount() (string, string) {
    ethPrivateKey := strings.TrimSpace(os.Getenv("ETHEREUM_PRIVATE_KEY"))
    if ethPrivateKey == "" {
        log.Fatal("ETHEREUM_PRIVATE_KEY is not set")
    }
    // Видаляємо префікс "0x", якщо він є
    if strings.HasPrefix(ethPrivateKey, "0x") || strings.HasPrefix(ethPrivateKey, "0X") {
        ethPrivateKey = ethPrivateKey[2:]
    }
    privateKeyBytes, err := crypto.HexToECDSA(ethPrivateKey)
    if err != nil {
        log.Fatalf("Invalid Ethereum private key: %v", err)
    }
    publicKeyECDSA := &privateKeyBytes.PublicKey
    ethAddress := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
    return ethPrivateKey, ethAddress
}

// Generate Paradex private key from Ethereum private key
func GenerateParadexAccount(config SystemConfigResponse, ethPrivateKey string) (string, string, string) {
    privateKey, _ := crypto.HexToECDSA(ethPrivateKey)
    ethSignature, _ := SignTypedData(typedData, privateKey)
    // Convert the first 32 bytes of ethSignature to a hex string
    r := hex.EncodeToString(ethSignature[:32])
    // Get Starknet curve order
    n := ecc.STARK_CURVE.ScalarField()
    dexPrivateKey := GrindKey(r, n)
    dexPrivateKeyBN := types.HexToBN(dexPrivateKey)
    dexPublicKeyBN, _, _ := caigo.Curve.PrivateToPoint(dexPrivateKeyBN)
    dexPublicKey := types.BigToHex(dexPublicKeyBN)
    dexAccountAddress := ComputeAddress(config, dexPublicKey)
    return dexPrivateKey, dexPublicKey, dexAccountAddress
}

// Get Paradex account using provided PARADEX_PRIVATE_KEY, if available,
// otherwise generate it from the Ethereum private key.
func GetParadexAccount(config SystemConfigResponse, ethPrivateKey string) (string, string, string) {
    providedKey := strings.TrimSpace(os.Getenv("PARADEX_PRIVATE_KEY"))
    if providedKey != "" {
        // Використовуємо наданий Paradex приватний ключ
        dexPrivateKey := providedKey
        dexPrivateKeyBN := types.HexToBN(dexPrivateKey)
        dexPublicKeyBN, _, err := caigo.Curve.PrivateToPoint(dexPrivateKeyBN)
        if err != nil {
            log.Fatalf("Failed to compute Paradex public key: %v", err)
        }
        dexPublicKey := types.BigToHex(dexPublicKeyBN)
        dexAccountAddress := ComputeAddress(config, dexPublicKey)
        return dexPrivateKey, dexPublicKey, dexAccountAddress
    }
    // Якщо PARADEX_PRIVATE_KEY не вказаний – генеруємо його на основі ETHEREUM_PRIVATE_KEY
    return GenerateParadexAccount(config, ethPrivateKey)
}

// Get ECDSA private key from string
func GetEcdsaPrivateKey(pk string) *ecdsa.PrivateKey {
    privateKey := types.StrToFelt(pk).Big()

    // Generate public key
    _, g := starkcurve.Generators()
    ecdsaPublicKey := new(ecdsa.PublicKey)
    ecdsaPublicKey.A.ScalarMultiplication(&g, privateKey)

    // Generate private key
    pkBytes := privateKey.FillBytes(make([]byte, fr.Bytes))
    buf := append(ecdsaPublicKey.Bytes(), pkBytes...)
    ecdsaPrivateKey := new(ecdsa.PrivateKey)
    ecdsaPrivateKey.SetBytes(buf)
    return ecdsaPrivateKey
}

func GnarkSign(messageHash *big.Int, privateKey string) (r, s *big.Int, err error) {
    ecdsaPrivateKey := GetEcdsaPrivateKey(privateKey)
    sigBin, err := ecdsaPrivateKey.Sign(messageHash.Bytes(), nil)
    if err != nil {
        return nil, nil, err
    }
    r = new(big.Int).SetBytes(sigBin[:fr.Bytes])
    s = new(big.Int).SetBytes(sigBin[fr.Bytes:])
    return r, s, nil
}

// `POST /onboarding`
func PerformOnboarding(
    config SystemConfigResponse,
    ethAddress string,
    dexPrivateKey string,
    dexPublicKey string,
    dexAccountAddress string,
) {
    dexAccountAddressBN := types.HexToBN(dexAccountAddress)

    // Get message hash and signature
    sc := caigo.StarkCurve{}
    message := &OnboardingPayload{Action: "Onboarding"}
    typedData, _ := NewVerificationTypedData(VerificationTypeOnboarding, config.ChainId)
    domEnc, _ := typedData.GetTypedMessageHash("StarkNetDomain", typedData.Domain, sc)
    messageHash, _ := GnarkGetMessageHash(typedData, domEnc, dexAccountAddressBN, message, sc)
    r, s, _ := GnarkSign(messageHash, dexPrivateKey)

    // URL
    onboardingUrl := fmt.Sprintf("%s/onboarding", PARADEX_HTTP_URL)

    // Body
    body := OnboardingReqBody{PublicKey: dexPublicKey}
    bodyByte, err := json.Marshal(body)
    if err != nil {
        Print("Unable to marshal body:", err)
    }

    // Request
    req, _ := http.NewRequest(http.MethodPost, onboardingUrl, bytes.NewReader(bodyByte))

    // Headers
    req.Header.Set("Content-Type", CONTENT_TYPE)
    req.Header.Add("PARADEX-ETHEREUM-ACCOUNT", ethAddress)
    req.Header.Add("PARADEX-STARKNET-ACCOUNT", dexAccountAddress)
    req.Header.Add("PARADEX-STARKNET-SIGNATURE", GetSignatureStr(r, s))

    // Response
    res, _ := http.DefaultClient.Do(req)
    Print("POST /onboarding:", res.Status)
}

// `POST /auth`
func GetJwtToken(
    config SystemConfigResponse,
    dexAccountAddress string,
    dexPrivateKey string,
) string {
    dexAccountAddressBN := types.HexToBN(dexAccountAddress)

    // Get timestamp and expiration
    now := time.Now().Unix()
    timestampStr := strconv.FormatInt(now, 10)
    expirationStr := strconv.FormatInt(now+DEFAULT_EXPIRY_IN_SECONDS, 10)

    // Get message hash and signature
    sc := caigo.StarkCurve{}
    message := &AuthPayload{
        Method:     "POST",
        Path:       "/v1/auth",
        Body:       "",
        Timestamp:  timestampStr,
        Expiration: expirationStr,
    }
    typedData, _ := NewVerificationTypedData(VerificationTypeAuth, config.ChainId)
    domEnc, _ := typedData.GetTypedMessageHash("StarkNetDomain", typedData.Domain, sc)
    messageHash, _ := GnarkGetMessageHash(typedData, domEnc, dexAccountAddressBN, message, sc)
    r, s, _ := GnarkSign(messageHash, dexPrivateKey)

    // URL
    authUrl := fmt.Sprintf("%s/auth", PARADEX_HTTP_URL)

    // Request
    req, _ := http.NewRequest(http.MethodPost, authUrl, nil)

    // Headers
    req.Header.Set("Content-Type", CONTENT_TYPE)
    req.Header.Add("PARADEX-STARKNET-ACCOUNT", dexAccountAddress)
    req.Header.Add("PARADEX-STARKNET-SIGNATURE", GetSignatureStr(r, s))
    req.Header.Add("PARADEX-TIMESTAMP", timestampStr)
    req.Header.Add("PARADEX-SIGNATURE-EXPIRATION", expirationStr)

    // Response
    res, _ := http.DefaultClient.Do(req)
    Print("POST /auth:", res.Status)

    jwtToken := ParsePostAuth(res)
    return jwtToken
}

// `GET /orders-history`
func GetOpenOrders(jwtToken string) []*Order {
    // URL updated per API sample
    ordersUrl := fmt.Sprintf("%s/orders-history", PARADEX_HTTP_URL)
    // Body with filtering parameters if needed
    body := OpenOrdersReqBody{Market: "BTC-USD-PERP"}
    bodyByte, err := json.Marshal(body)
    if err != nil {
        Print("Unable to marshal body:", err)
    }
    req, _ := http.NewRequest(http.MethodGet, ordersUrl, bytes.NewReader(bodyByte))
    req.Header.Set("Content-Type", CONTENT_TYPE)
    bearer := fmt.Sprintf("Bearer %s", jwtToken)
    req.Header.Add("Authorization", bearer)

    res, _ := http.DefaultClient.Do(req)
    Print("GET /orders-history:", res.Status)
    orders := ParseGetOrders(res)
    return orders
}

// Додаємо нову функцію для отримання найкращої ціни біду
func GetBestBid(market string) float64 {
    url := fmt.Sprintf("%s/bbo/%s", PARADEX_HTTP_URL, market)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        log.Printf("Помилка створення запиту: %v", err)
        return 0
    }
    req.Header.Set("Accept", "application/json")
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Помилка виконання запиту: %v", err)
        return 0
    }
    defer resp.Body.Close()
    var bboResp struct {
        Bid string `json:"bid"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&bboResp); err != nil {
        log.Printf("Помилка декодування відповіді: %v", err)
        return 0
    }
    bidPrice, err := strconv.ParseFloat(bboResp.Bid, 64)
    if err != nil {
        log.Printf("Помилка перетворення ціни: %v", err)
        return 0
    }
    return bidPrice
}

// New function to get the best ask price.
func GetBestAsk(market string) float64 {
    url := fmt.Sprintf("%s/bbo/%s", PARADEX_HTTP_URL, market)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        log.Printf("Помилка створення запиту: %v", err)
        return 0
    }
    req.Header.Set("Accept", "application/json")
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Помилка виконання запиту: %v", err)
        return 0
    }
    defer resp.Body.Close()
    var bboResp struct {
        Ask string `json:"ask"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&bboResp); err != nil {
        log.Printf("Помилка декодування відповіді: %v", err)
        return 0
    }
    askPrice, err := strconv.ParseFloat(bboResp.Ask, 64)
    if err != nil {
        log.Printf("Помилка перетворення ціни: %v", err)
        return 0
    }
    return askPrice
}

// Updated SubmitGridOrders: orders placed ±5% around midPrice with 0.1% step.
func SubmitGridOrders(
    config SystemConfigResponse,
    dexAccountAddress string,
    dexPrivateKey string,
    jwtToken string,
) {
    market := "BTC-USD-PERP"
    currentPrice := (GetBestBid(market) + GetBestAsk(market)) / 2
    Print(fmt.Sprintf("Current market price: %.2f", currentPrice))

    // Calculate boundaries and step
    gridStep := currentPrice * 0.001  // Exactly 0.1% step
    lowerLimit := currentPrice * 0.95 // -5% from current price
    upperLimit := currentPrice * 1.05 // +5% from current price

    Print(fmt.Sprintf("Grid setup: Lower=%.2f, Upper=%.2f, Step=%.2f", lowerLimit, upperLimit, gridStep))

    sc := caigo.StarkCurve{}
    typedData, _ := NewVerificationTypedData("Order", config.ChainId)
    domEnc, _ := typedData.GetTypedMessageHash("StarkNetDomain", typedData.Domain, sc)

    limiter := time.NewTicker(5 * time.Millisecond)
    defer limiter.Stop()
    var wg sync.WaitGroup

    // Calculate number of orders needed in each direction
    numSteps := int((0.05 * currentPrice) / gridStep) // 5% range with 0.1% steps = 50 steps each direction

    // Place BUY orders from current price down to -5%
    for i := 1; i <= numSteps; i++ {
        orderPrice := currentPrice * (1 - float64(i)*0.001) // Subtract 0.1% each step
        if orderPrice < lowerLimit {
            break
        }

        price := strconv.FormatFloat(orderPrice, 'f', 2, 64)
        timestamp := time.Now().UnixMilli()

        orderPayload := &OrderPayload{
            Timestamp: timestamp,
            Market:    market,
            Side:      "BUY",
            OrderType: "LIMIT",
            Size:      "1",
            Price:     price,
        }

        wg.Add(1)
        go func(i int, price string, orderPayload *OrderPayload, timestamp int64) {
            defer wg.Done()
            <-limiter.C

            messageHash, _ := GnarkGetMessageHash(typedData, domEnc, types.HexToBN(dexAccountAddress), orderPayload, sc)
            r, s, _ := GnarkSign(messageHash, dexPrivateKey)

            ordersUrl := fmt.Sprintf("%s/orders", PARADEX_HTTP_URL)
            body := OrderRequest{
                Market:             market,
                Side:               OrderSide("BUY"),
                Type:               OrderType("LIMIT"),
                Size:               "1",
                Price:              price,
                Signature:          GetSignatureStr(r, s),
                SignatureTimestamp: timestamp,
            }

            bodyByte, err := json.Marshal(body)
            if err != nil {
                Print("Unable to marshal body:", err)
                return
            }

            req, _ := http.NewRequest(http.MethodPost, ordersUrl, bytes.NewReader(bodyByte))
            req.Header.Set("Content-Type", CONTENT_TYPE)
            req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

            res, _ := http.DefaultClient.Do(req)
            Print(fmt.Sprintf("POST /orders [BUY] grid order %d at price %s: %s", i, price, res.Status))
        }(i, price, orderPayload, timestamp)
    }

    // Place SELL orders from current price up to +5%
    for i := 1; i <= numSteps; i++ {
        orderPrice := currentPrice * (1 + float64(i)*0.001) // Add 0.1% each step
        if orderPrice > upperLimit {
            break
        }

        price := strconv.FormatFloat(orderPrice, 'f', 2, 64)
        timestamp := time.Now().UnixMilli()

        orderPayload := &OrderPayload{
            Timestamp: timestamp,
            Market:    market,
            Side:      "SELL",
            OrderType: "LIMIT",
            Size:      "1",
            Price:     price,
        }

        wg.Add(1)
        go func(i int, price string, orderPayload *OrderPayload, timestamp int64) {
            defer wg.Done()
            <-limiter.C

            messageHash, _ := GnarkGetMessageHash(typedData, domEnc, types.HexToBN(dexAccountAddress), orderPayload, sc)
            r, s, _ := GnarkSign(messageHash, dexPrivateKey)

            ordersUrl := fmt.Sprintf("%s/orders", PARADEX_HTTP_URL)
            body := OrderRequest{
                Market:             market,
                Side:               OrderSide("SELL"),
                Type:               OrderType("LIMIT"),
                Size:               "1",
                Price:              price,
                Signature:          GetSignatureStr(r, s),
                SignatureTimestamp: timestamp,
            }

            bodyByte, err := json.Marshal(body)
            if err != nil {
                Print("Unable to marshal body:", err)
                return
            }

            req, _ := http.NewRequest(http.MethodPost, ordersUrl, bytes.NewReader(bodyByte))
            req.Header.Set("Content-Type", CONTENT_TYPE)
            req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

            res, _ := http.DefaultClient.Do(req)
            Print(fmt.Sprintf("POST /orders [SELL] grid order %d at price %s: %s", i, price, res.Status))
        }(i, price, orderPayload, timestamp)
    }

    wg.Wait()
    Print("Grid orders placement completed")
}

func CancelExistingOrders(jwtToken string, market string) error {
    // Create empty JSON body
    emptyBody := "{}"

    // Create request with proper URL
    url := fmt.Sprintf("%s/orders", PARADEX_HTTP_URL)
    req, err := http.NewRequest(http.MethodDelete, url, bytes.NewBuffer([]byte(emptyBody)))
    if err != nil {
        return fmt.Errorf("failed to create request: %v", err)
    }

    // Set required headers per API spec
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

    // Execute request
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("failed to execute request: %v", err)
    }
    defer resp.Body.Close()

    // Check response
    if resp.StatusCode != http.StatusOK {
        var errorResp struct {
            Error   string `json:"error"`
            Message string `json:"message"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
            return fmt.Errorf("failed with status %d", resp.StatusCode)
        }
        return fmt.Errorf("failed to cancel orders: %s - %s", errorResp.Error, errorResp.Message)
    }

    Print("Successfully cancelled all orders")
    return nil
}

func ExampleSignMultipleOrders() {
    privateKey := GetEcdsaPrivateKey("X")
    accountAddress := big.NewInt(0)
    sc := caigo.StarkCurve{}
    td, _ := NewVerificationTypedData("Order", "PRIVATE_SN_POTC_SEPOLIA")
    domEnc, _ := td.GetTypedMessageHash("StarkNetDomain", td.Domain, sc)

    for j := 0; j < 10; j++ {
        start := time.Now()
        for i := 0; i < 100000; i++ {
            orderP := &OrderPayload{
                Timestamp: time.Now().UnixMilli(),
                Market:    "ETH-USD-PERP",
                Side:      "SELL",
                OrderType: "LIMIT",
                Size:      strconv.Itoa(4 + i),
                Price:     strconv.Itoa(5900 + i),
            }
            messageHash, _ := GnarkGetMessageHash(td, domEnc, accountAddress, orderP, sc)
            sigBin, err := privateKey.Sign(messageHash.Bytes(), nil)
            if err != nil {
                Print("Error:", err)
            }
            valid, _ := privateKey.PublicKey.Verify(sigBin, messageHash.Bytes(), nil)
            if !valid {
                Print("Invalid signature")
            }
        }
        Print("Average time taken:", time.Since(start).Seconds()/100000)
    }
}

func main() {
    // Load Paradex config
    paradexConfig, _ := GetParadexConfig()

    // Initialize Ethereum account
    ethPrivateKey, ethAddress := GetEthereumAccount()

    // Generate Paradex account – using PARADEX_PRIVATE_KEY if set
    dexPrivateKey, dexPublicKey, dexAccountAddress := GetParadexAccount(paradexConfig, ethPrivateKey)

    // Onboard generated Paradex account
    PerformOnboarding(
        paradexConfig,
        ethAddress,
        dexPrivateKey,
        dexPublicKey,
        dexAccountAddress,
    )

    // Get a JWT token to interact with private endpoints
    jwtToken := GetJwtToken(
        paradexConfig,
        dexAccountAddress,
        dexPrivateKey,
    )

    // Check for existing orders on the same market; if any exist, cancel them.
    existingOrders := GetOpenOrders(jwtToken)
    if len(existingOrders) > 0 {
        Print("Found existing orders, cancelling them...")
        CancelExistingOrders(jwtToken, "BTC-USD-PERP")
    }

    // Place new grid orders
    SubmitGridOrders(paradexConfig, dexAccountAddress, dexPrivateKey, jwtToken)
}

