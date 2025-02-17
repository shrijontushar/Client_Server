from app import app, db, User

with app.app_context():
    # Check if an admin already exists
    admin_user = User.query.filter_by(role='admin').first()
    
    if admin_user:
        print(f"Admin exists: {admin_user.username}")
    else:
        # Create a new admin user if none exists
        print("No admin found. Creating admin user.")
        new_admin = User(username='admin', email='admin@example.com', role='admin')
        new_admin.set_password('admin123')  # Set a password for the admin user
        db.session.add(new_admin)
        db.session.commit()
        print("Admin user created successfully.")
