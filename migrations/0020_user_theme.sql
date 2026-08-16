CREATE TABLE IF NOT EXISTS user_preferences (
    user_id INTEGER PRIMARY KEY,
    preferred_theme VARCHAR(16),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
