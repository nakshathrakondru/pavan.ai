from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import firebase_admin
from firebase_admin import auth,credentials, db
from firebase_admin.auth import verify_id_token
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from dotenv import load_dotenv
import os
import pytz
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from sendgrid import SendGridAPIClient
import requests
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition, ContentId
import threading
import base64
from io import BytesIO
from datetime import datetime
from datetime import timedelta
from urllib.parse import quote
import time
from apscheduler.executors.pool import ThreadPoolExecutor

# Load environment variables
load_dotenv()

cred = credentials.Certificate('pavanai-53e34-firebase-adminsdk-ubvnx-4b3b9c62ba.json')
SECRET_KEY = os.getenv('SECRET_KEY')
FIREBASE_CRED_PATH = os.getenv('FIREBASE_CRED_PATH')
FIREBASE_DB_URL = os.getenv('FIREBASE_DB_URL')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app and session
app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SERVER_NAME'] = 'localhost:5000' 
app.secret_key = SECRET_KEY

# Initialize CORS
CORS(app, resources={r"/*": {"origins": "*"}})  # Restrict origins in production
# Set up SendGrid API key (Use environment variable for security)

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
IQAIR_API_KEY = os.getenv('IQAIR_API_KEY')

# Initialize Firebase Admin SDK
if not os.path.exists(FIREBASE_CRED_PATH):
    logger.error("Firebase credentials file not found.")
    raise FileNotFoundError(f"Firebase credentials file not found at: {FIREBASE_CRED_PATH}")

cred = credentials.Certificate(FIREBASE_CRED_PATH)
firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})

tz = pytz.timezone('Asia/Kolkata')

# Initialize APScheduler
scheduler = BackgroundScheduler(executors={'default': ThreadPoolExecutor(10)})

scheduler.configure(timezone=tz)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",  # Replace with your Redis server's URI
    app=app
)

def classify_aqi(aqi):
    if aqi <= 50:
        return "Good", "Air quality is considered satisfactory, and air pollution poses little or no risk.", "Enjoy outdoor activities; no precautions needed."
    elif aqi <= 100:
        return "Moderate", "Air quality is acceptable, but there may be some health concerns for a small number of people who are sensitive to air pollution.", "Consider reducing prolonged outdoor activities if sensitive."
    elif aqi <= 150:
        return "Unhealthy for Sensitive Groups", "People with respiratory or heart conditions may experience health effects. The general public is less likely to be affected.", "Sensitive individuals should limit outdoor activities."
    elif aqi <= 200:
        return "Unhealthy", "Everyone may begin to experience health effects; members of sensitive groups may experience more serious effects.", "Limit outdoor activities for everyone. Sensitive groups should stay indoors."
    elif aqi <= 300:
        return "Very Unhealthy", "Health alert: everyone may experience more serious health effects.", "Avoid outdoor activities for everyone. Keep indoor air clean."
    else:
        return "Hazardous", "Health warning of emergency conditions. The entire population is likely to be affected.", "Stay indoors, and use an air purifier if available."

def fetch_aqi_data(city, state):
    try:
        city_encoded = quote(city)
        state_encoded = quote(state)
        url = f"http://api.airvisual.com/v2/city?city={city_encoded}&state={state_encoded}&country=India&key={IQAIR_API_KEY}"
        response = requests.get(url)
        data = response.json()

        # Check if the response is successful
        if response.status_code == 200 and data.get("status") == "success":
            # Safely extract AQI value and handle any missing data
            aqi = data["data"]["current"]["pollution"].get("aqius", None)  # AQI (US standard)
            
            if aqi is None:
                print(f"Warning: AQI data is missing for {city}, {state}")
                return 0, "N/A", "AQI data missing", "No suggestions available"

            # Call a separate function to classify the AQI
            aqi_level, description, suggestions = classify_aqi(aqi)

            return aqi, aqi_level, description, suggestions
        
        # Handle rate-limiting or other errors
        elif response.status_code == 429:  # Too Many Requests
            print(f"Rate limit exceeded for {city}, {state}. Retrying in 60 seconds...")
            time.sleep(60)  # Retry after waiting
            return fetch_aqi_data(city, state)  # Recursive call to retry the request

        else:
            print(f"Error: Failed to fetch AQI data for {city}, {state}. Response: {data}")
            return 0, "N/A", "AQI data not available", "No suggestions available"
    
    except Exception as e:
        print(f"Error fetching AQI data for {city}, {state}: {e}")
        return 0, "N/A", "Error fetching AQI data", "No suggestions available"

def generate_graph(aqi_values, aqi_dates,city):
    try:
        aqi_dates = [datetime.strptime(date, "%Y-%m-%d") for date in aqi_dates]
        plt.figure(figsize=(10, 6))
        plt.plot(aqi_dates, aqi_values, marker='o', linestyle='-', color='b', label='AQI')
        plt.title("AQI Over the Last 7 Days for {}".format(city))
        plt.xlabel("Date")
        plt.ylabel("AQI")
        plt.xticks(rotation=45)
        plt.grid(True)
        plt.tight_layout()

        img_buffer = BytesIO()
        plt.savefig(img_buffer, format="png")
        img_buffer.seek(0)
        encoded_graph = base64.b64encode(img_buffer.read()).decode("utf-8")
        img_buffer.close()
        plt.close()

        return encoded_graph
    except Exception as e:
        logging.error(f"Error generating graph: {e}")
        return None

def send_email_with_graph(user_email, user_name, city, state, aqi, aqi_level, aqi_description, aqi_suggestion, encoded_graph):
    try:
        dynamic_data = {
            "user_name": user_name,
            "city": city,
            "state": state,
            "aqi_value": aqi,
            "aqi_level": aqi_level,
            "aqi_description": aqi_description,
            "aqi_suggestions": aqi_suggestion,
        }

        # Check if dynamic data is correct
        logging.debug(f"Dynamic Data: {dynamic_data}")

        # Create email with SendGrid
        message = Mail(
            from_email='teamsiriius@gmail.com',
            to_emails=user_email,
        )
        message.dynamic_template_data = dynamic_data
        message.template_id = "d-9bd4eb0cec0446c3b866d67d71e496ae"  # Verify template ID is correct

        # Prepare the attachment
        attachment = Attachment(
            FileContent(encoded_graph),
            FileName(f"{city}_aqi_trend.png"),
            FileType("image/png"),
            Disposition("inline"),
            ContentId("aqi_trend.png")
        )

        message.add_attachment(attachment)

        # Log the email details
        logging.debug(f"Sending email to: {user_email}")

        sg = SendGridAPIClient(SENDGRID_API_KEY)

        # Send the email
        response = sg.send(message)

        # Check the response status code
        if response.status_code == 202:
            logging.info("Email sent successfully!")
        else:
            logging.error(f"Failed to send email. Response code: {response.status_code}")
            logging.error(f"Response body: {response.body}")
            logging.error(f"Response headers: {response.headers}")
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")

def send_aqi_notification_to_all_users():
    print("Job triggered: sending AQI notifications")
    try:
        users_ref = db.reference("users")
        users = users_ref.get()

        if not users:
            logging.warning("No users found.")
            return

        for user_id, user_data in users.items():
            email = user_data.get("email")
            preferences = user_data.get("preferences")

            if email and preferences:
                for pref_id, pref_data in preferences.items():
                    city = pref_data.get("city")
                    state = pref_data.get("state")

                    if city and state:
                        aqi_ref = db.reference(f"AQI_Data/{state}/{city}")
                        aqi_snapshot = aqi_ref.get()

                        # Corrected logic to handle missing or incomplete data gracefully
                        if aqi_snapshot and isinstance(aqi_snapshot, list):
                            # Filter for valid entries and get the last 7 days
                            valid_entries = [entry for entry in aqi_snapshot if entry and entry.get("date") and entry.get("aqi") is not None]
                            last_7_entries = valid_entries[-7:]
                            
                            aqi_values = [entry["aqi"] for entry in last_7_entries]
                            aqi_dates = [entry["date"] for entry in last_7_entries]
                        else:
                            # Use placeholders if no valid data is found
                            aqi_values = [0] * 7
                            today = datetime.now()
                            aqi_dates = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
                            
                        encoded_graph = generate_graph(aqi_values, aqi_dates, city)
                        
                        if encoded_graph:
                            aqi, aqi_level, description, suggestions = fetch_aqi_data(city, state)

                            send_email_with_graph(
                                email,
                                user_data.get("username"),
                                city,
                                state,
                                aqi,
                                aqi_level,
                                description,
                                suggestions,
                                encoded_graph
                            )
                            logging.info(f"Successfully sent AQI notification to {email} for {city}, {state}")
                        else:
                            logging.error(f"Failed to generate graph for {city}.")
                    else:
                        logging.warning(f"Skipping user {user_id} preference: Missing city or state.")
                # Add interval between each user's preferences
                time.sleep(2)
            else:
                logging.warning(f"Skipping user {user_id}: Missing email or preferences.")
    except Exception as e:
        logging.error(f"Error in send_aqi_notification_to_all_users: {e}")

def start_scheduler():
    # Ensure the scheduler is running only once
    if not scheduler.get_job('send_aqi_notification_to_all_users'):
        scheduler.add_job(
            send_aqi_notification_to_all_users, 
            'cron', 
            hour=22, 
            minute=40, 
            second=0, 
            id='send_aqi_notification_to_all_users'
        )
    scheduler.start()

# Start scheduler in a separate thread only once
def start_scheduler_thread():
    scheduler_thread = threading.Thread(target=start_scheduler)
    scheduler_thread.daemon = True  # Ensure the thread exits when the main program exits
    if not scheduler_thread.is_alive():
        scheduler_thread.start()

# Call this function at the start of your application
start_scheduler_thread()

firebase_ref = db.reference()
# Utility function to verify Firebase ID tokens
def verify_user_token(id_token):
    try:
        decoded_token = verify_id_token(id_token)
        email = decoded_token.get('email')
        uid = decoded_token.get('uid')
        return email, uid
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return None, 'Token verification failed'

# Decorator for login-required routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    """Render the home page."""
    user_email = session.get('user_email')
    return render_template('home.html', user_email=user_email)

@app.route('/login-page', methods=['GET'])
def login_page():
    """Render the login page."""
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Handle manual login with Firebase Authentication."""
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        if not id_token:
            return jsonify({'success': False, 'message': 'Missing ID token'}), 400

        email, uid_or_error = verify_user_token(id_token)
        
        # Check if the UID was returned successfully
        if not email:
            return jsonify({'success': False, 'message': uid_or_error}), 401

        # If the token is valid, store the email and UID in the session
        session['user_email'] = email
        session['user_uid'] = uid_or_error  # Save the UID in session

        return jsonify({'success': True, 'message': 'Login successful'})

    except Exception as e:
        logger.error(f"Unexpected error in login: {e}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500

@app.route('/google-login', methods=['POST'])
def google_login():
    try:
        data = request.get_json()
        id_token_received = data.get('idToken')
        if not id_token_received:
            return jsonify({'success': False, 'message': 'Missing ID token'}), 400
        
        # Verify the Google ID token using Firebase Admin SDK
        try:
            decoded_token = auth.verify_id_token(id_token_received)
            email = decoded_token['email']
            uid = decoded_token['uid']
        except firebase_admin.exceptions.FirebaseError as e:
            return jsonify({'success': False, 'message': 'Token verification failed', 'error': str(e)}), 401
        
        # Save the user's email and UID to the session
        session['user_email'] = email
        session['user_uid'] = uid
        
        return jsonify({'success': True, 'message': 'Google login successful'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': 'An unexpected error occurred', 'error': str(e)}), 500
@app.route('/register')
def registration_page():
    return render_template('registration.html')

@app.route('/logout')
def logout():
    """Logout the user and clear session."""
    session.clear()
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    """Fetch user data and render the profile page."""
    try:
        user_uid = session.get('user_uid')  # Get UID from session
        if not user_uid:
            return redirect(url_for('login_page'))  # Redirect to login if no UID found

        # Reference to Firebase Realtime Database
        user_ref = db.reference(f'users/{user_uid}')
        user_data = user_ref.get()  # Fetch data from Firebase

        if not user_data:
            return jsonify({'success': False, 'message': 'User data not found'}), 404

        # Return user data to be rendered in the profile page
        return render_template('profile.html', user=user_data)

    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while fetching user details'}), 500

@app.route('/user/<user_uid>', methods=['GET'])
@login_required
def get_user_data(user_uid):
    """Get user details based on UID."""
    try:
        print(f"Fetching data for user UID: {user_uid}")  # Debugging line
        user_ref = db.reference(f'users/{user_uid}')
        user_data = user_ref.get()

        if not user_data:
            print('User data not found')  # Debugging line
            return jsonify({'success': False, 'message': 'User not found'}), 404

        print(f"User data: {user_data}")  # Debugging line
        return jsonify({'success': True, 'user': user_data}), 200
    except Exception as e:
        print(f"Error fetching user data: {str(e)}")  # Debugging line
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/preferences', methods=['GET'])
def get_preferences():
    """Get the user’s saved preferences."""
    try:
        user_uid = session.get('user_uid')
        preferences_ref = db.reference(f'users/{user_uid}/preferences')
        preferences = preferences_ref.get()

        if not preferences:
            return jsonify({'success': False, 'message': 'No preferences found.'}), 404

        return jsonify({'success': True, 'preferences': preferences})

    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while fetching preferences'}), 500

@app.route('/preferences/delete', methods=['POST'])
def delete_preferences():
    """Delete a specific preference."""
    try:
        preference_key = request.form.get('preferenceKey')

        if not preference_key:
            return jsonify({'success': False, 'message': 'Preference key is required.'}), 400

        user_uid = session.get('user_uid')
        preference_ref = db.reference(f'users/{user_uid}/preferences/{preference_key}')
        preference_ref.delete()

        return jsonify({'success': True, 'message': 'Preference deleted successfully'})

    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while deleting the preference'}), 500

@app.route('/send_preferences_email', methods=['POST'])
def send_preferences_email():
    try:
        # Get user data from the request
        user_data = request.json
        user_email = user_data.get('email')

        if not user_email:
            return jsonify({"success": False, "message": "User email is missing."})

        # Retrieve user UID from session
        user_uid = session.get('user_uid')
        if not user_uid:
            return jsonify({"success": False, "message": "User UID is missing from session."})

        # Fetch preferences from Firebase
        preferences_ref = db.reference(f'users/{user_uid}/preferences')
        preferences_snapshot = preferences_ref.get()
        
        if not preferences_snapshot:
            return jsonify({"success": False, "message": "No preferences found for this user."})

        # Fetch user data from Firebase
        user_ref = db.reference(f'users/{user_uid}')
        user_snapshot = user_ref.get()
        user_name = user_snapshot.get('username', "User")  # Default to "User" if username is not found

        # Format preferences as a list of dictionaries (objects)
        preferences_data = [
            {"state": pref.get('state', "Unknown"), "city": pref.get('city', "Unknown")}
            for pref in preferences_snapshot.values()
        ]

        # Debugging output to verify data
        print("User email:", user_email)
        print("User UID:", user_uid)
        print("Preferences data:", preferences_data)

        # Define dynamic template data for SendGrid
        dynamic_data = {
            "preferences": preferences_data,
            "user_name": user_name,
        }

        # Send email using SendGrid Dynamic Template
        message = Mail(
            from_email='teamsiriius@gmail.com',
            to_emails=user_email,
        )
        message.dynamic_template_data = dynamic_data
        message.template_id = "d-7de09e2901b742d8a74d38276629d52d"  # Ensure this ID matches your template

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)

        # Log the SendGrid response for debugging
        print("SendGrid response status:", response.status_code)
        print("SendGrid response body:", response.body.decode('utf-8') if response.body else "No body content")
        print("SendGrid response headers:", response.headers)

        if response.status_code == 202:
            return jsonify({"success": True, "message": "Email sent successfully using the dynamic template."})
        else:
            return jsonify({"success": False, "message": "Failed to send email."})

    except Exception as e:
        # Log the error for debugging
        print("Error occurred:", str(e))
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"})

@app.route('/about-us', methods=['GET'])
def about_page():
    """Render the login page."""
    return render_template('about.html')

if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
    while True:
        time.sleep(1) 
