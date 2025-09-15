package main

import (
    "net/http"
    "time"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
    ID       string `json:"id"`
    Username string `json:"username"`
    Password string `json:"password,omitempty"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
}

// album represents data about a record album.
type album struct {
    ID     string  `json:"id"`
    Title  string  `json:"title"`
    Artist string  `json:"artist"`
    Price  float64 `json:"price"`
}

var (
    // Secret key for JWT signing (in production, use environment variable)
    jwtSecret = []byte("your-secret-key-change-this-in-production")
    
    // Mock user database (in production, use real database)
    users = []User{
        {ID: "1", Username: "admin", Password: "$2a$10$YKyCqY8WxLrKvEwHwqKvLOqVxx6VgX8RS6pAP8Km6ll8Lf6vNEEGy"}, // password: admin123
        {ID: "2", Username: "user", Password: "$2a$10$PZoG5U0W0az3gXXfJ6h.4.lPmKz3p8J2B8o/A7iqGgSrqvE3vXJZ."}, // password: user123
    }
    
    // albums slice to seed record album data.
    albums = []album{
        {ID: "1", Title: "Blue Train", Artist: "John Coltrane", Price: 56.99},
        {ID: "2", Title: "Jeru", Artist: "Gerry Mulligan", Price: 17.99},
        {ID: "3", Title: "Sarah Vaughan and Clifford Brown", Artist: "Sarah Vaughan", Price: 39.99},
    }
)

// Claims represents JWT claims
type Claims struct {
    Username string `json:"username"`
    UserID   string `json:"user_id"`
    jwt.RegisteredClaims
}

func main() {
    router := gin.Default()
    
    // Public routes (no authentication required)
    router.POST("/login", login)
    router.POST("/register", register)
    
    // Protected routes (authentication required)
    protected := router.Group("/")
    protected.Use(authMiddleware())
    {
        protected.GET("/albums", getAlbums)
        protected.GET("/albums/:id", getAlbumByID)
        protected.POST("/albums", postAlbums)
        protected.DELETE("/albums/:id", deleteAlbum)
    }

    router.Run("localhost:8080")
}

// authMiddleware validates JWT token
func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get token from Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }
        
        // Check if header starts with "Bearer "
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
            c.Abort()
            return
        }
        
        tokenString := parts[1]
        
        // Parse and validate token
        token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
            return jwtSecret, nil
        })
        
        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
            c.Abort()
            return
        }
        
        // Store user info in context
        if claims, ok := token.Claims.(*Claims); ok {
            c.Set("username", claims.Username)
            c.Set("user_id", claims.UserID)
        }
        
        c.Next()
    }
}

// login authenticates user and returns JWT token
func login(c *gin.Context) {
    var req LoginRequest
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Find user
    var foundUser *User
    for _, user := range users {
        if user.Username == req.Username {
            foundUser = &user
            break
        }
    }
    
    if foundUser == nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }
    
    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(req.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }
    
    // Generate JWT token
    token, err := generateToken(foundUser.Username, foundUser.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "token": token,
        "user": gin.H{
            "id":       foundUser.ID,
            "username": foundUser.Username,
        },
    })
}

// register creates a new user
func register(c *gin.Context) {
    var req LoginRequest
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Check if user already exists
    for _, user := range users {
        if user.Username == req.Username {
            c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
            return
        }
    }
    
    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }
    
    // Create new user
    newUser := User{
        ID:       generateID(),
        Username: req.Username,
        Password: string(hashedPassword),
    }
    
    users = append(users, newUser)
    
    // Generate token for new user
    token, err := generateToken(newUser.Username, newUser.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }
    
    c.JSON(http.StatusCreated, gin.H{
        "token": token,
        "user": gin.H{
            "id":       newUser.ID,
            "username": newUser.Username,
        },
    })
}

// generateToken creates a new JWT token
func generateToken(username, userID string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    
    claims := &Claims{
        Username: username,
        UserID:   userID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

// generateID creates a simple ID (in production, use UUID)
func generateID() string {
    return time.Now().Format("20060102150405")
}

// getAlbums responds with the list of all albums as JSON.
func getAlbums(c *gin.Context) {
    // You can access authenticated user info if needed
    username := c.GetString("username")
    c.Header("X-Authenticated-User", username)
    
    c.IndentedJSON(http.StatusOK, albums)
}

// postAlbums adds an album from JSON received in the request body.
func postAlbums(c *gin.Context) {
    var newAlbum album

    if err := c.BindJSON(&newAlbum); err != nil {
        return
    }

    albums = append(albums, newAlbum)
    c.IndentedJSON(http.StatusCreated, newAlbum)
}

// getAlbumByID locates the album whose ID value matches the id
func getAlbumByID(c *gin.Context) {
    id := c.Param("id")

    for _, a := range albums {
        if a.ID == id {
            c.IndentedJSON(http.StatusOK, a)
            return
        }
    }
    c.IndentedJSON(http.StatusNotFound, gin.H{"message": "album not found"})
}

// deleteAlbum removes an album by ID
func deleteAlbum(c *gin.Context) {
    id := c.Param("id")
    
    for i, a := range albums {
        if a.ID == id {
            albums = append(albums[:i], albums[i+1:]...)
            c.JSON(http.StatusOK, gin.H{"message": "album deleted"})
            return
        }
    }
    
    c.JSON(http.StatusNotFound, gin.H{"message": "album not found"})
}