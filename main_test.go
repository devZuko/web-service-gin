package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Helpers

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	// Rotas públicas
	r.POST("/login", login)
	r.POST("/register", register)

	// Rotas protegidas
	protected := r.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/albums", getAlbums)
		protected.GET("/albums/:id", getAlbumByID)
		protected.POST("/albums", postAlbums)
		protected.DELETE("/albums/:id", deleteAlbum)
	}

	return r
}

func performRequest(r *gin.Engine, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Reset do estado global para isolamento entre testes
func resetState() {
	users = []User{
		{ID: "1", Username: "admin", Password: "$2a$10$YKyCqY8WxLrKvEwHwqKvLOqVxx6VgX8RS6pAP8Km6ll8Lf6vNEEGy"}, // admin123
		{ID: "2", Username: "user", Password: "$2a$10$PZoG5U0W0az3gXXfJ6h.4.lPmKz3p8J2B8o/A7iqGgSrqvE3vXJZ."}, // user123
	}
	albums = []album{
		{ID: "1", Title: "Blue Train", Artist: "John Coltrane", Price: 56.99},
		{ID: "2", Title: "Jeru", Artist: "Gerry Mulligan", Price: 17.99},
		{ID: "3", Title: "Sarah Vaughan and Clifford Brown", Artist: "Sarah Vaughan", Price: 39.99},
	}
}

func getValidToken(t *testing.T) string {
	t.Helper()
	token, err := generateToken("admin", "1")
	if err != nil {
		t.Fatalf("erro ao gerar token: %v", err)
	}
	return token
}

// 1) Login com sucesso
func TestLoginSuccess(t *testing.T) {
	resetState()
	router := setupRouter()

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin123",
	})
	w := performRequest(router, http.MethodPost, "/login", body, "")

	if w.Code != http.StatusOK {
		t.Fatalf("status esperado 200, obtido %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Token string                 `json:"token"`
		User  map[string]interface{} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("falha ao decodificar resposta: %v", err)
	}
	if resp.Token == "" {
		t.Fatalf("token não retornado")
	}
	if resp.User["id"] != "1" || resp.User["username"] != "admin" {
		t.Fatalf("payload do usuário inesperado: %#v", resp.User)
	}
}

// 2) Login com senha inválida
func TestLoginInvalidPassword(t *testing.T) {
	resetState()
	router := setupRouter()

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "senha_errada",
	})
	w := performRequest(router, http.MethodPost, "/login", body, "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status esperado 401, obtido %d: %s", w.Code, w.Body.String())
	}
}

// 3) Acesso a rota protegida sem token
func TestProtectedNoToken(t *testing.T) {
	resetState()
	router := setupRouter()

	w := performRequest(router, http.MethodGet, "/albums", nil, "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status esperado 401, obtido %d: %s", w.Code, w.Body.String())
	}
}

// 4) Listar álbuns com token válido e checar header de usuário autenticado
func TestGetAlbumsWithToken(t *testing.T) {
	resetState()
	router := setupRouter()
	token := getValidToken(t)

	w := performRequest(router, http.MethodGet, "/albums", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("status esperado 200, obtido %d: %s", w.Code, w.Body.String())
	}

	if got := w.Header().Get("X-Authenticated-User"); got != "admin" {
		t.Fatalf("esperado header X-Authenticated-User=admin, obtido %q", got)
	}

	var resp []album
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("falha ao decodificar resposta: %v", err)
	}
	if len(resp) != 3 {
		t.Fatalf("esperado 3 álbuns, obtido %d", len(resp))
	}
}

// 5) Registro com username existente (deve retornar 409)
func TestRegisterConflict(t *testing.T) {
	resetState()
	router := setupRouter()

	body, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "qualquer",
	})
	w := performRequest(router, http.MethodPost, "/register", body, "")

	if w.Code != http.StatusConflict {
		t.Fatalf("status esperado 409, obtido %d: %s", w.Code, w.Body.String())
	}
}