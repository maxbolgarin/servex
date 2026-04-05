package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/maxbolgarin/servex/v2"
)

// This example demonstrates a complete REST API for task management
// with JWT authentication, role-based access control, CRUD operations,
// input validation, and pagination.
//
// Run:
//
//	go run main.go
//
// Test:
//
//	# Login as demo user
//	TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
//	  -H "Content-Type: application/json" \
//	  -d '{"username":"demo","password":"demo1234"}' | jq -r .accessToken)
//
//	# Create a task
//	curl -s -X POST http://localhost:8080/api/v1/tasks \
//	  -H "Authorization: Bearer $TOKEN" \
//	  -H "Content-Type: application/json" \
//	  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}' | jq .
//
//	# List tasks with pagination
//	curl -s "http://localhost:8080/api/v1/tasks?page=1&limit=5" \
//	  -H "Authorization: Bearer $TOKEN" | jq .
//
//	# Login as admin
//	ADMIN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
//	  -H "Content-Type: application/json" \
//	  -d '{"username":"admin","password":"admin123"}' | jq -r .accessToken)
//
//	# List all tasks (admin only)
//	curl -s http://localhost:8080/api/v1/admin/tasks \
//	  -H "Authorization: Bearer $ADMIN" | jq .
func main() {
	store := NewTaskStore()

	server, err := servex.NewServer(servex.MergeWithPreset(
		servex.APIServerPreset(),
		servex.WithAuthMemoryDatabase(),
		servex.WithAuthInitialUsers(
			servex.InitialUser{
				Username: "admin",
				Password: "admin123",
				Roles:    []servex.UserRole{"admin", "user"},
			},
			servex.InitialUser{
				Username: "demo",
				Password: "demo1234",
				Roles:    []servex.UserRole{"user"},
			},
		),
		servex.WithHealthEndpoint(),
		servex.WithDefaultMetrics(),
	)...)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	// Task CRUD (any authenticated user with "user" role)
	api := server.Group("/api/v1")
	api.GetWithAuth("/tasks", store.ListTasks, "user")
	api.PostWithAuth("/tasks", store.CreateTask, "user")
	api.GetWithAuth("/tasks/{id}", store.GetTask, "user")
	api.PutWithAuth("/tasks/{id}", store.UpdateTask, "user")
	api.DeleteWithAuth("/tasks/{id}", store.DeleteTask, "user")

	// Admin endpoints
	api.GetWithAuth("/admin/tasks", store.AdminListAllTasks, "admin")
	api.GetWithAuth("/admin/stats", store.AdminStats, "admin")

	fmt.Println("Servex REST API Server — Task Management")
	fmt.Println("Server: http://localhost:8080")
	fmt.Println()
	fmt.Println("Auth:  POST /api/v1/auth/{register,login,refresh,logout}")
	fmt.Println("       Users: admin/admin123 (admin), demo/demo1234 (user)")
	fmt.Println()
	fmt.Println("Tasks: GET    /api/v1/tasks?page=1&limit=10&status=pending")
	fmt.Println("       POST   /api/v1/tasks")
	fmt.Println("       GET    /api/v1/tasks/{id}")
	fmt.Println("       PUT    /api/v1/tasks/{id}")
	fmt.Println("       DELETE /api/v1/tasks/{id}")
	fmt.Println()
	fmt.Println("Admin: GET /api/v1/admin/tasks")
	fmt.Println("       GET /api/v1/admin/stats")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	if err := server.StartWithWaitSignalsHTTP(context.Background(), ":8080"); err != nil {
		log.Fatal(err)
	}
}

// Task represents a task in the system.
type Task struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // pending, in_progress, done
	OwnerID     string    `json:"owner_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateTaskRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

type UpdateTaskRequest struct {
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	Status      *string `json:"status,omitempty"`
}

type PaginatedResponse struct {
	Data       any `json:"data"`
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

var validStatuses = map[string]bool{
	"pending":     true,
	"in_progress": true,
	"done":        true,
}

// TaskStore is a thread-safe in-memory task store.
type TaskStore struct {
	mu     sync.RWMutex
	tasks  map[string]*Task
	nextID int
}

func NewTaskStore() *TaskStore {
	return &TaskStore{
		tasks: make(map[string]*Task),
	}
}

// CreateTask handles POST /api/v1/tasks.
func (s *TaskStore) CreateTask(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)

	var req CreateTaskRequest
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}
	if req.Title == "" {
		ctx.BadRequest(nil, "title is required")
		return
	}

	now := time.Now().UTC()
	s.mu.Lock()
	s.nextID++
	task := &Task{
		ID:          strconv.Itoa(s.nextID),
		Title:       req.Title,
		Description: req.Description,
		Status:      "pending",
		OwnerID:     userID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.tasks[task.ID] = task
	s.mu.Unlock()

	ctx.Response(http.StatusCreated, task)
}

// GetTask handles GET /api/v1/tasks/{id}.
func (s *TaskStore) GetTask(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)
	id := ctx.Path("id")

	s.mu.RLock()
	task, ok := s.tasks[id]
	s.mu.RUnlock()

	if !ok {
		ctx.NotFound(nil, "task not found")
		return
	}
	if task.OwnerID != userID {
		ctx.Forbidden(nil, "access denied")
		return
	}

	ctx.JSON(task)
}

// ListTasks handles GET /api/v1/tasks with pagination and optional status filter.
func (s *TaskStore) ListTasks(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)

	page, _ := strconv.Atoi(ctx.Query("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(ctx.Query("limit"))
	if limit < 1 || limit > 100 {
		limit = 10
	}
	statusFilter := ctx.Query("status")

	s.mu.RLock()
	var filtered []*Task
	for _, t := range s.tasks {
		if t.OwnerID != userID {
			continue
		}
		if statusFilter != "" && t.Status != statusFilter {
			continue
		}
		filtered = append(filtered, t)
	}
	s.mu.RUnlock()

	total := len(filtered)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	ctx.JSON(PaginatedResponse{
		Data:       filtered[start:end],
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: int(math.Ceil(float64(total) / float64(limit))),
	})
}

// UpdateTask handles PUT /api/v1/tasks/{id}. Only the owner can update.
func (s *TaskStore) UpdateTask(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)
	id := ctx.Path("id")

	var req UpdateTaskRequest
	if err := ctx.ReadJSON(&req); err != nil {
		ctx.BadRequest(err, "invalid request body")
		return
	}

	if req.Status != nil && !validStatuses[*req.Status] {
		ctx.BadRequest(nil, "status must be one of: pending, in_progress, done")
		return
	}

	s.mu.Lock()
	task, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		ctx.NotFound(nil, "task not found")
		return
	}
	if task.OwnerID != userID {
		s.mu.Unlock()
		ctx.Forbidden(nil, "only the task owner can update")
		return
	}

	if req.Title != nil {
		task.Title = *req.Title
	}
	if req.Description != nil {
		task.Description = *req.Description
	}
	if req.Status != nil {
		task.Status = *req.Status
	}
	task.UpdatedAt = time.Now().UTC()
	s.mu.Unlock()

	ctx.JSON(task)
}

// DeleteTask handles DELETE /api/v1/tasks/{id}. Owner or admin can delete.
func (s *TaskStore) DeleteTask(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)
	userID := r.Context().Value(servex.UserContextKey{}).(string)
	roles := r.Context().Value(servex.RoleContextKey{}).([]servex.UserRole)
	id := ctx.Path("id")

	isAdmin := false
	for _, role := range roles {
		if role == "admin" {
			isAdmin = true
			break
		}
	}

	s.mu.Lock()
	task, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		ctx.NotFound(nil, "task not found")
		return
	}
	if task.OwnerID != userID && !isAdmin {
		s.mu.Unlock()
		ctx.Forbidden(nil, "only the task owner or admin can delete")
		return
	}
	delete(s.tasks, id)
	s.mu.Unlock()

	ctx.Response(http.StatusNoContent)
}

// AdminListAllTasks handles GET /api/v1/admin/tasks. Returns all tasks.
func (s *TaskStore) AdminListAllTasks(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	s.mu.RLock()
	all := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		all = append(all, t)
	}
	s.mu.RUnlock()

	ctx.JSON(all)
}

// AdminStats returns task statistics across all users (admin only).
func (s *TaskStore) AdminStats(w http.ResponseWriter, r *http.Request) {
	ctx := servex.C(w, r)

	s.mu.RLock()
	statusCounts := map[string]int{
		"pending":     0,
		"in_progress": 0,
		"done":        0,
	}
	owners := make(map[string]int)
	for _, t := range s.tasks {
		statusCounts[t.Status]++
		owners[t.OwnerID]++
	}
	s.mu.RUnlock()

	ctx.JSON(map[string]any{
		"total_tasks":    len(statusCounts),
		"by_status":      statusCounts,
		"tasks_by_owner": owners,
	})
}
