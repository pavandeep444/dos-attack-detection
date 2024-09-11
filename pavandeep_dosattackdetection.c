#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define THRESHOLD 1000  // Requests per second threshold for DOS detection
#define MAX_REQUESTS 10000
#define TIME_WINDOW 5  // Time window in seconds for monitoring

// Simulate incoming requests
int simulate_incoming_requests() {
    return rand() % MAX_REQUESTS;
}

// Function to detect DOS attack
void detect_dos_attack() {
    int request_count = 0;
    time_t start_time = time(NULL);

    printf("Monitoring incoming traffic...\n");

    while (1) {
        // Simulate incoming requests
        int incoming_requests = simulate_incoming_requests();
        request_count += incoming_requests;

        // Calculate elapsed time
        time_t current_time = time(NULL);
        double elapsed_time = difftime(current_time, start_time);

        // Check if time window has passed
        if (elapsed_time >= TIME_WINDOW) {
            printf("Time window: %.0f seconds | Requests: %d\n", elapsed_time, request_count);

            // Check if the request count exceeds the threshold
            if (request_count > THRESHOLD * TIME_WINDOW) {
                printf("DOS attack detected! Too many requests: %d\n", request_count);
            } else {
                printf("Traffic is normal.\n");
            }

            // Reset for next window
            request_count = 0;
            start_time = current_time;
        }

        // Sleep for a short period to simulate real-time monitoring
        sleep(1);
    }
}

int main() {
    srand(time(NULL));  // Seed for random number generation
    detect_dos_attack();
    return 0;
}
