#!/bin/bash

# Function to start the Go server
start_go_server() {
  echo "Starting Go server..."
  cd backend
  go run main.go &
  GO_PID=$!
  cd ..
}

# Function to start the React app
start_react_app() {
  echo "Starting React app..."
  cd frontend
  npm start &
  REACT_PID=$!
  cd ..
}

# Function to stop both servers
stop_servers() {
  echo "Stopping servers..."
  kill $GO_PID
  kill $REACT_PID
}

# Start servers
start_go_server
start_react_app

# Trap to stop servers on script exit
trap stop_servers EXIT

# Wait for servers to exit
wait

