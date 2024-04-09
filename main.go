package main

import (
	"bytes"
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3" // Import go-sqlite3 package
)

// Structs

type PageSkeletonData struct {
	PageTitle  string
	PageName   string
	Main       template.HTML
	Users      []User
	IsLoggedIn bool
}

type User struct {
	ID       int
	Username string
	Password string
}

// Variables
var userDB string = "./db/users.db"
var dbType string = "sqlite3"
var skellyTemplate string = "static/html/skelly.html"
var registerPartial string = "static/html/register.html"
var loginPartial string = "static/html/login.html"
var dashboardPartial string = "static/html/dashboard.html"
var store = sessions.NewCookieStore([]byte("your-secret-key"))

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/register", registrationHandler)
	r.HandleFunc("/login-submit", loginSubmitHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/dashboard", dashboardHandler)
	r.HandleFunc("/logout", logoutHandler)

	initDB()

	log.Fatal(http.ListenAndServe(":8081", r))
}

func initDB() {
	db, err := sql.Open(dbType, userDB)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTableSQL := `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}

}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	skellyTemplate, err := template.ParseFiles(skellyTemplate)
	if err != nil {
		http.Error(w, "Great Big Buggy Error", http.StatusInternalServerError)
		return
	}

	userTemplate, err := template.ParseFiles(registerPartial)
	if err != nil {
		log.Printf("Error parsing user template: %v", err)
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	users, err := getUsersFromDB()
	if err != nil {
		log.Printf("Error getting users from DB: %v", err)
		http.Error(w, "Failed to gather users from database", http.StatusInternalServerError)
		return
	}

	var userContent bytes.Buffer
	err = userTemplate.Execute(&userContent, users)
	if err != nil {
		log.Printf("Error combining database content via buffer with template")
		http.Error(w, "Server problem", http.StatusInternalServerError)
		return
	}

	// Check if the user is logged in by trying to get the session
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
	}

	isLoggedIn := false
	if session.Values["username"] != nil {
		isLoggedIn = true
	}

	pageData := PageSkeletonData{
		PageTitle:  "Registration",
		PageName:   "Register your account",
		Main:       template.HTML(userContent.String()),
		IsLoggedIn: isLoggedIn,
	}

	err = skellyTemplate.Execute(w, pageData)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	indexTemplate, err := template.ParseFiles(skellyTemplate)
	if err != nil {
		http.Error(w, "Great Big Buggy Error", http.StatusInternalServerError)
		return
	}

	pageContent, err := os.ReadFile(loginPartial)
	if err != nil {
		http.Error(w, "Great Big Buggy Error", http.StatusInternalServerError)
		return
	}

	pageData := PageSkeletonData{
		PageTitle: "Login",
		PageName:  "Login to your account",
		Main:      template.HTML(pageContent),
	}

	indexTemplate.Execute(w, pageData)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session, err := store.Get(r, "session-name")
	if err != nil {
		// Handle error
		http.Error(w, "Session retrieval failed", http.StatusInternalServerError)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Prepare the data to pass to the dashboard template, including the username
	data := struct {
		Username string
	}{
		Username: username,
	}
	// Assuming dashboardPartial is the path to your dashboard template.
	dashboardTemplate, err := template.ParseFiles(dashboardPartial)
	if err != nil {
		log.Printf("Error parsing dashboard template: %v", err)
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}
	var dashboardContent bytes.Buffer
	err = dashboardTemplate.Execute(&dashboardContent, data)
	if err != nil {
		log.Printf("Error executing dashboard template into buffer: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Parse the skeleton template
	skellyTemplate, err := template.ParseFiles(skellyTemplate)
	if err != nil {
		http.Error(w, "Error parsing skeleton template", http.StatusInternalServerError)
		return
	}

	// Check if the user is logged in by trying to get the session

	isLoggedIn := false
	if session.Values["username"] != nil {
		isLoggedIn = true
	}

	pageData := PageSkeletonData{
		PageTitle:  "Dashboard",
		PageName:   "Dashboard",
		Main:       template.HTML(dashboardContent.String()), // Use the buffer's content
		IsLoggedIn: isLoggedIn,
	}

	// Execute the skeleton template with the dashboard content included
	err = skellyTemplate.Execute(w, pageData)
	if err != nil {
		log.Printf("Error executing skeleton template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

}

func loginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Form submission must be of type POST", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to understand form inputs", http.StatusBadRequest)
		return
	}
	username := r.FormValue("user")
	password := r.FormValue("password")

	if username == "" {
		http.Error(w, "Username Can't be empty", http.StatusBadRequest)
	} else if password == "" {
		http.Error(w, "Password can't be empty", http.StatusBadRequest)
	}

	user, err := userLookupForLogin(username, password)
	if err != nil {
		http.Error(w, "Login authentication procedure failed", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	if user != nil {
		log.Println("Login Successfull")
		session, _ := store.Get(r, "session-name")
		session.Values["username"] = username // Assuming "username" is the key
		session.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	} else {
		log.Println("Login Failed")
		http.Error(w, "User not found", http.StatusBadRequest)
	}

}

func userLookupForLogin(username, password string) (*User, error) {
	db, err := sql.Open(dbType, userDB)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT id, username, password FROM users WHERE username = ? AND password = ?", username, password).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("User not found")
			return nil, nil
		}
		return nil, err
	}

	return &user, nil

}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Form submission must be of type POST", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to understand form inputs", http.StatusBadRequest)
		return
	}

	username := r.FormValue("user")
	password := r.FormValue("password")

	if username == "" {
		http.Error(w, "Username Can't be empty", http.StatusBadRequest)
	} else if password == "" {
		http.Error(w, "Password can't be empty", http.StatusBadRequest)
	}

	db, err := sql.Open(dbType, userDB)
	if err != nil {
		http.Error(w, "Database insertion failed", http.StatusInternalServerError)
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
	if err != nil {
		http.Error(w, "Failed to insert user into database", http.StatusInternalServerError)
		log.Println(err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getUsersFromDB() ([]User, error) {
	var users []User

	db, err := sql.Open(dbType, userDB)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, username, password FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session
	session, err := store.Get(r, "session-name")
	if err != nil {
		// Handle error, maybe log it and redirect with an error message
		http.Error(w, "Could not get session", http.StatusInternalServerError)
		return
	}

	// Clearing the session. You can do this by setting MaxAge to -1
	session.Options.MaxAge = -1

	// Saving the changes to the session.
	err = session.Save(r, w)
	if err != nil {
		// Handle error, maybe log it and redirect with an error message
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}

	// Redirecting to the login page or home page after logout
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
