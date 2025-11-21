
# Create comprehensive data structure for the HealQueue system
# This will be used to inform the application generation

import json

# Define the complete system architecture and data flows
healqueue_architecture = {
    "roles": [
        {
            "id": 1,
            "name": "admin",
            "display_name": "Administrator",
            "permissions": [
                "user_management",
                "role_management",
                "system_analytics",
                "queue_insights",
                "audit_logs",
                "full_control"
            ],
            "dashboard_features": [
                "User/Role Management",
                "System Analytics",
                "Queue Insights",
                "Audit Logs",
                "Database Management"
            ]
        },
        {
            "id": 2,
            "name": "doctor",
            "display_name": "Doctor",
            "permissions": [
                "view_assigned_patients",
                "mark_consultation",
                "update_patient_status",
                "view_patient_history"
            ],
            "dashboard_features": [
                "Assigned Patients List",
                "Consultation Marking",
                "Patient Status Updates",
                "Patient History"
            ]
        },
        {
            "id": 3,
            "name": "receptionist",
            "display_name": "Receptionist",
            "permissions": [
                "register_patient",
                "issue_token",
                "manage_queue",
                "update_appointment"
            ],
            "dashboard_features": [
                "Patient Registration",
                "Token Issuance",
                "Queue Management",
                "Appointment Updates"
            ]
        },
        {
            "id": 4,
            "name": "nurse",
            "display_name": "Nurse",
            "permissions": [
                "pre_check_updates",
                "vitals_entry",
                "patient_movement",
                "queue_progression"
            ],
            "dashboard_features": [
                "Pre-check Updates",
                "Vitals Entry",
                "Patient Movement",
                "Queue Progression"
            ]
        }
    ],
    
    "queue_states": [
        {"id": 1, "name": "waiting", "display": "Waiting", "color": "#FFA500"},
        {"id": 2, "name": "in_progress", "display": "In Progress", "color": "#2196F3"},
        {"id": 3, "name": "completed", "display": "Completed", "color": "#4CAF50"},
        {"id": 4, "name": "cancelled", "display": "Cancelled", "color": "#F44336"}
    ],
    
    "sample_doctors": [
        {"id": 1, "name": "Dr. Sarah Johnson", "specialty": "Cardiology", "available": True},
        {"id": 2, "name": "Dr. Michael Chen", "specialty": "Pediatrics", "available": True},
        {"id": 3, "name": "Dr. Emily Rodriguez", "specialty": "Orthopedics", "available": False},
        {"id": 4, "name": "Dr. James Williams", "specialty": "General Medicine", "available": True}
    ],
    
    "sample_queue_data": [
        {
            "token": "TOK001",
            "patient_name": "John Doe",
            "age": 45,
            "department": "Cardiology",
            "status": "waiting",
            "wait_time_minutes": 25,
            "registration_time": "09:15 AM"
        },
        {
            "token": "TOK002",
            "patient_name": "Jane Smith",
            "age": 32,
            "department": "Pediatrics",
            "status": "in_progress",
            "wait_time_minutes": 10,
            "registration_time": "09:30 AM"
        },
        {
            "token": "TOK003",
            "patient_name": "Robert Brown",
            "age": 58,
            "department": "General Medicine",
            "status": "waiting",
            "wait_time_minutes": 15,
            "registration_time": "09:45 AM"
        }
    ],
    
    "announcements": [
        {
            "id": 1,
            "title": "Emergency Department Delay",
            "message": "Due to high patient volume, emergency department wait times may be longer than usual.",
            "priority": "high",
            "timestamp": "2025-11-18 09:00 AM"
        },
        {
            "id": 2,
            "title": "Dr. Rodriguez Unavailable",
            "message": "Dr. Emily Rodriguez is currently unavailable. Orthopedics appointments will be rescheduled.",
            "priority": "medium",
            "timestamp": "2025-11-18 08:30 AM"
        }
    ],
    
    "team_members": [
        {
            "name": "Dr. Sarah Johnson",
            "role": "Chief of Cardiology",
            "image": "doctor1",
            "bio": "15+ years of experience in cardiovascular medicine"
        },
        {
            "name": "Michael Anderson",
            "role": "Head Receptionist",
            "image": "receptionist1",
            "bio": "Ensuring smooth patient check-ins since 2015"
        },
        {
            "name": "Emily Chen",
            "role": "Senior Nurse",
            "image": "nurse1",
            "bio": "Specialized in patient care and vitals monitoring"
        },
        {
            "name": "Admin Team",
            "role": "System Administrators",
            "image": "admin1",
            "bio": "Managing hospital operations and technology"
        }
    ]
}

# Save to JSON for app generation
with open('healqueue_data.json', 'w') as f:
    json.dump(healqueue_architecture, f, indent=2)

print("HealQueue architecture data created successfully")
print(f"Total roles defined: {len(healqueue_architecture['roles'])}")
print(f"Sample queue entries: {len(healqueue_architecture['sample_queue_data'])}")
print(f"Team members: {len(healqueue_architecture['team_members'])}")
