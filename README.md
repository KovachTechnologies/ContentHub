# ContentHub
A Flask-based web application for delivering educational content with secure user authentication, course progress tracking, and leaderboards. Built with SQLite for user management and bcrypt for password hashing, this LMS is designed for small-scale e-learning platforms with a modular structure for easy extension.

## Features
- **User Management**: Secure registration, login, logout, and password change with SQLite and bcrypt.
- **Course Delivery**: Structured content delivery with progress tracking.
- **Leaderboards**: Displays user rankings based on quiz performance.
- **Admin Dashboard**: Restricted access for managing users in the same group.
- **Modular Design**: Easy to extend with additional features or integrate with other systems.

## Tech Stack
- **Backend**: Flask (Python)
- **Database**: SQLite with Flask-SQLAlchemy
- **Security**: bcrypt for password hashing
- **Frontend**: HTML templates with static assets (CSS, JS, images)

## Setup Instructions

### Prerequisites
- Python 3.8+
- Git
- Virtualenv (recommended)

### Installation
1. Clone the repository:
```bash
git clone https://github.com/KovachTechnologies/ContentHub.git
cd ContentHub
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set the `SECRET_KEY` environment variable:
```bash
export SECRET_KEY='your-secret-key'  # On Windows: set SECRET_KEY=your-secret-key
```

5. Run the application:
```bash
python app.py
```

6. Access the LMS at `http://localhost:5001`.

## Database
* The application uses SQLite (users.db) for user data.
* The database is automatically created on the first run.

## Usage
* **Register**: Create a new account via the /register route.
* **Login**: Access the system at /login.
* **Courses**: Navigate through course content and answer quizzes.
* **Leaderboard**: View user rankings at /leaderboard.
* **Admin**: Admins can access the /admin dashboard for group-specific data.

## Development
* **Testing**: Add unit tests with pytest (not included yet).
* **Extending**: Add new routes or features in app.py and update templates as needed.
* **Production**: Use a WSGI server like Gunicorn and consider PostgreSQL for scalability.

## Contributing
* Contributions are welcome! Please follow these steps:
* Fork the repository.
* Create a feature branch (git checkout -b feature/your-feature).
* Commit your changes (git commit -m 'Add your feature').
* Push to the branch (git push origin feature/your-feature).
* Open a Pull Request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
