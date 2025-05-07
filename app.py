from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_bcrypt import Bcrypt
from flask_session import Session
import mysql.connector
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "super_secret_key"

# Configure session
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

bcrypt = Bcrypt(app)

# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="shubhanshu@08",
    database="ecc_shield"
)
cursor = db.cursor()

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key().decode()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_password))
            db.commit()
            flash("Signup successful! Please login.", "success")
            return redirect(url_for("login"))
        except:
            flash("Username already exists!", "danger")

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(url_for("main_page"))
        else:
            flash("Invalid credentials", "danger")

    return render_template("login.html")

@app.route("/input")
def input_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("input.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    title = request.form["title"]
    message = request.form["message"]
    encryption_key = generate_key()

    cipher = Fernet(encryption_key.encode())
    encrypted_content = cipher.encrypt(message.encode()).decode()

    cursor.execute(
        "INSERT INTO encryptions (user_id, title, encrypted_content, encryption_key) VALUES (%s, %s, %s, %s)", 
        (user_id, title, encrypted_content, encryption_key)
    )
    db.commit()

    flash("Message encrypted successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/main")
def main_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("main.html")

@app.route("/inputfile")
def file_input_page():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("inputfile.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    
    # Fetch text encryptions
    cursor.execute("SELECT * FROM encryptions WHERE user_id = %s", (user_id,))
    owned_encryptions = cursor.fetchall()

    cursor.execute("SELECT * FROM encryptions WHERE shared_with LIKE %s", (f"%{session['username']}%",))
    shared_encryptions = cursor.fetchall()

    # Fetch file encryptions with owner information
    cursor.execute("""
        SELECT ef.*, u.username as owner_name 
        FROM encrypted_files ef
        JOIN users u ON ef.user_id = u.id
        WHERE ef.user_id = %s
    """, (user_id,))
    owned_files = cursor.fetchall()

    cursor.execute("""
        SELECT ef.*, u.username as owner_name 
        FROM encrypted_files ef
        JOIN users u ON ef.user_id = u.id
        WHERE ef.shared_with LIKE %s
    """, (f"%{session['username']}%",))
    shared_files = cursor.fetchall()

    # Fetch available users for sharing
    cursor.execute("SELECT username FROM users WHERE username != %s", (session["username"],))
    users = [user[0] for user in cursor.fetchall()]

    return render_template(
        "dashboard.html", 
        owned_encryptions=owned_encryptions, 
        shared_encryptions=shared_encryptions,
        owned_files=owned_files,
        shared_files=shared_files,
        users=users
    )

@app.route("/decrypt", methods=["POST"])
def decrypt():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized access"}), 403

    data = request.get_json()
    encryption_id = data.get("encryption_id")

    cursor.execute("SELECT encrypted_content, encryption_key FROM encryptions WHERE id = %s", (encryption_id,))
    result = cursor.fetchone()

    if not result:
        return jsonify({"success": False, "error": "Invalid encryption ID"}), 400

    encrypted_content, encryption_key = result

    try:
        cipher = Fernet(encryption_key.encode())
        decrypted_content = cipher.decrypt(encrypted_content.encode()).decode()
        return jsonify({"success": True, "decrypted_content": decrypted_content})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/delete/<int:encryption_id>", methods=["POST"])
def delete_encryption(encryption_id):
    cursor.execute("DELETE FROM encryptions WHERE id = %s", (encryption_id,))
    db.commit()
    flash("Message deleted successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/revoke/<int:encryption_id>", methods=["POST"])
def revoke_access(encryption_id, revoke_user_id):
    cursor = db.cursor()

    # Fetch current shared users
    cursor.execute("SELECT shared_with FROM encryptions WHERE id = %s", (encryption_id,))
    result = cursor.fetchone()
    
    if not result or not result[0]:  # No shared users
        return

    shared_users = result[0].split(",")  # Convert string to list
    if str(revoke_user_id) in shared_users:
        shared_users.remove(str(revoke_user_id))  # Remove selected user

    # Convert list back to string and update DB
    updated_shared_with = ",".join(shared_users) if shared_users else None  # If empty, set to NULL
    cursor.execute("UPDATE encryptions SET shared_with = %s WHERE id = %s", (updated_shared_with, encryption_id))
    db.commit()
    cursor.close()


@app.route("/revoke", methods=["POST"])
def revoke_access_handler():  # Changed function name
    encryption_id = request.form.get("encryption_id")
    revoke_user = request.form.get("revoke_user")

    print(f"DEBUG: Received revoke request for encryption_id={encryption_id}, revoke_user={revoke_user}")

    if not encryption_id or not revoke_user:
        return "Invalid Request", 400

    # Fetch current shared_with list
    cursor = db.cursor()
    cursor.execute("SELECT shared_with FROM encryptions WHERE id = %s", (encryption_id,))
    result = cursor.fetchone()
    
    if not result or not result[0]:
        return "No users to revoke", 400

    shared_users = result[0].split(",")
    
    if revoke_user not in shared_users:
        return "User not found in shared list", 400

    # Remove user from shared list
    shared_users.remove(revoke_user)
    new_shared_with = ",".join(shared_users) if shared_users else None

    cursor.execute("UPDATE encryptions SET shared_with = %s WHERE id = %s", (new_shared_with, encryption_id))
    db.commit()
    cursor.close()

    return redirect("/dashboard")




@app.route("/share", methods=["POST"])
def share():
    if "user_id" not in session:
        return redirect(url_for("login"))

    encryption_id = request.form["encryption_id"]
    shared_with = request.form["shared_with"]

    cursor.execute("SELECT shared_with FROM encryptions WHERE id = %s", (encryption_id,))
    current_shared = cursor.fetchone()[0] or ""

    updated_shared = ",".join(set(current_shared.split(",") + [shared_with])) if current_shared else shared_with

    cursor.execute("UPDATE encryptions SET shared_with = %s WHERE id = %s", (updated_shared, encryption_id))
    db.commit()

    flash("Encryption shared successfully!", "success")
    return redirect(url_for("dashboard"))


@app.route("/get_shared_users", methods=["GET"])
def get_shared_users():
    encryption_id = request.args.get("encryption_id")
    cursor = db.cursor()
    
    cursor.execute("SELECT shared_with FROM encryptions WHERE id = %s", (encryption_id,))
    result = cursor.fetchone()
    
    if result and result[0]:
        shared_users = result[0].split(",")
    else:
        shared_users = []  # Empty if no users found
    
    cursor.close()
    
    print(f"DEBUG: Shared user IDs for encryption_id {encryption_id} -> {shared_users}")
    
    return jsonify(shared_users)




def share_encryption(encryption_id, shared_user_id):
    cursor = db.cursor()

    # Fetch the current shared_with field
    cursor.execute("SELECT shared_with FROM encryptions WHERE id = %s", (encryption_id,))
    result = cursor.fetchone()
    
    if result and result[0]:  # If already shared
        shared_users = result[0].split(",")  # Convert to list
        if str(shared_user_id) not in shared_users:  # Avoid duplicate entries
            shared_users.append(str(shared_user_id))
    else:
        shared_users = [str(shared_user_id)]  # If empty, start new list

    # Convert list back to string and update the DB
    updated_shared_with = ",".join(shared_users)
    cursor.execute("UPDATE encryptions SET shared_with = %s WHERE id = %s", (updated_shared_with, encryption_id))
    db.commit()
    cursor.close()

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


@app.route("/encrypt_file", methods=["POST"])
def encrypt_file():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    title = request.form["title"]
    uploaded_file = request.files["file"]

    if not uploaded_file or uploaded_file.filename == "":
        flash("No file selected", "danger")
        return redirect(url_for("file_input_page"))

    # Generate encryption key
    encryption_key = generate_key()
    cipher = Fernet(encryption_key.encode())

    # Read file data
    file_data = uploaded_file.read()
    file_name = uploaded_file.filename
    file_type = uploaded_file.content_type

    # Encrypt the file data
    encrypted_data = cipher.encrypt(file_data)

    # Store in database
    try:
        cursor.execute(
            """INSERT INTO encrypted_files 
            (user_id, title, file_name, file_type, encrypted_data, encryption_key) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (user_id, title, file_name, file_type, encrypted_data, encryption_key)
        )
        db.commit()
        flash("File encrypted and stored successfully!", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error encrypting file: {str(e)}", "danger")

    return redirect(url_for("dashboard"))

def get_user_by_id(user_id):
    cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    return {"username": result[0]} if result else None

@app.route("/decrypt_file/<int:file_id>")
def decrypt_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Check if user has access to this file
    cursor.execute(
        """SELECT * FROM encrypted_files 
        WHERE id = %s AND (user_id = %s OR shared_with LIKE %s)""",
        (file_id, session["user_id"], f"%{session['username']}%")
    )
    file_record = cursor.fetchone()

    if not file_record:
        flash("File not found or access denied", "danger")
        return redirect(url_for("dashboard"))

    try:
        # Decrypt the file data
        cipher = Fernet(file_record[6].encode())  # encryption_key is at index 6
        decrypted_data = cipher.decrypt(file_record[5])  # encrypted_data is at index 5

        # Create a response with the decrypted file
        response = make_response(decrypted_data)
        response.headers.set('Content-Type', file_record[4])  # file_type is at index 4
        response.headers.set('Content-Disposition', 'attachment', 
                           filename=file_record[3])  # file_name is at index 3
        
        return response

    except Exception as e:
        flash(f"Error decrypting file: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/share_file", methods=["POST"])
def share_file():
    if "user_id" not in session:
        return redirect(url_for("login"))

    file_id = request.form["file_id"]
    shared_with = request.form["shared_with"]

    cursor.execute("SELECT shared_with FROM encrypted_files WHERE id = %s", (file_id,))
    current_shared = cursor.fetchone()[0] or ""

    updated_shared = ",".join(set(current_shared.split(",") + [shared_with])) if current_shared else shared_with

    cursor.execute("UPDATE encrypted_files SET shared_with = %s WHERE id = %s", (updated_shared, file_id))
    db.commit()

    flash("File shared successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete_file/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    cursor.execute("DELETE FROM encrypted_files WHERE id = %s AND user_id = %s", 
                  (file_id, session["user_id"]))
    db.commit()
    flash("File deleted successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/revoke_file_access", methods=["POST"])
def revoke_file_access():
    if "user_id" not in session:
        return redirect(url_for("login"))

    file_id = request.form.get("file_id")
    username_to_revoke = request.form.get("username")

    if not file_id or not username_to_revoke:
        flash("Invalid request", "danger")
        return redirect(url_for("dashboard"))

    # Verify current user owns the file
    cursor.execute("SELECT user_id, shared_with FROM encrypted_files WHERE id = %s", (file_id,))
    file_data = cursor.fetchone()

    if not file_data or file_data[0] != session["user_id"]:
        flash("File not found or access denied", "danger")
        return redirect(url_for("dashboard"))

    # Handle None case for shared_with
    shared_with = file_data[1] or ""
    shared_users = [user.strip() for user in shared_with.split(",") if user.strip()]
    
    if username_to_revoke in shared_users:
        shared_users.remove(username_to_revoke)
        updated_shared_with = ",".join(shared_users) if shared_users else None

        cursor.execute(
            "UPDATE encrypted_files SET shared_with = %s WHERE id = %s",
            (updated_shared_with, file_id)
        )
        db.commit()
        flash(f"Access revoked for {username_to_revoke}", "success")
    else:
        flash("User not found in shared list", "warning")

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
