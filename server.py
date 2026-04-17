import os
import sqlite3
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_url_path='', static_folder='.')

# ---------------------------------------------------------
# GEMINI SETUP
# ---------------------------------------------------------
# Ensure you have your API key set in your environment:
# export GEMINI_API_KEY="your-api-key"
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))

# ---------------------------------------------------------
# DATABASE TOOL SETUP
# ---------------------------------------------------------
def prepare_database():
    """Loads CSVs into an SQLite memory database."""
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    
    # Load Lead Time Data
    if os.path.exists('cve_lead_time.csv'):
        df_lead = pd.read_csv('cve_lead_time.csv')
        df_lead.to_sql('cve_lead_time', conn, index=False)
        
    # Load Reddit Posts Data
    if os.path.exists('reddit_cve_posts.csv'):
        df_posts = pd.read_csv('reddit_cve_posts.csv')
        df_posts.to_sql('reddit_cve_posts', conn, index=False)
        
    return conn

db_connection = prepare_database()

def execute_sql_query(sql_query: str) -> str:
    """
    Executes a SQL query against the SQLite database containing the CVE and Reddit data.
    Tables available: 
    - cve_lead_time (columns: cve, post_count, earliest_post_iso_utc, cvss_score, cvss_severity, vuln_status, vendors, lead_days, subreddits)
    - reddit_cve_posts (columns: post_id, subreddit, title, body, url, cves, created_iso_utc)
    
    Args:
        sql_query: The SQL query to execute.
    """
    try:
        df = pd.read_sql_query(sql_query, db_connection)
        return df.to_json(orient="records")
    except Exception as e:
        return str(e)

# Create the Gemini tool list
tools = [execute_sql_query]

# System Instructions
system_instruction = """
You are a highly skilled Cyber Threat Intelligence Agent and SecOps Analyst.
Your job is to answer user questions about CVEs (Common Vulnerabilities and Exposures) and Threat Intelligence.
You have access to a SQL database containing two tables:
1. `cve_lead_time`: Contains aggregated info about CVEs, their NVD CVSS scores, vendors, and how many days it was discussed on Reddit before NVD publication.
2. `reddit_cve_posts`: Contains the raw Reddit posts (title, body, subreddit, url) where these CVEs were discussed.

Use the `execute_sql_query` tool to search for data whenever the user asks a question about specific CVEs, vendors, severities, or Reddit discussions.
ALWAYS answer in clean Markdown format with bullet points and bold text where appropriate. Be concise but act like a professional security analyst.
If the SQL query returns an error, try to fix your query and run it again.
"""

# Initialize model
try:
    model = genai.GenerativeModel(
        model_name="gemini-2.5-flash", # Fast, high-tier model
        tools=tools,
        system_instruction=system_instruction
    )
except Exception as e:
    # Fallback for older SDKs
    model = genai.GenerativeModel("gemini-pro")

# Store conversation per session (simplified for local use)
chat_session = None

# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    global chat_session
    
    if not os.environ.get("GEMINI_API_KEY"):
        return jsonify({"error": "GEMINI_API_KEY environment variable is not set. Please set it and restart the server."}), 500

    data = request.json
    user_message = data.get("message", "")
    
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
        
    try:
        # Re-initialize chat if None
        if chat_session is None:
            chat_session = model.start_chat(enable_automatic_function_calling=True)
            
        print(f"User asking: {user_message}")
        response = chat_session.send_message(user_message)
    except Exception as e:
        # Try to re-init just in case
        try:
            chat_session = model.start_chat(enable_automatic_function_calling=True)
            response = chat_session.send_message(user_message)
        except Exception as inner_e:
            return jsonify({"error": str(inner_e)}), 500

    return jsonify({"response": response.text})

if __name__ == '__main__':
    print("Starting AI SecOps Server...")
    print("Dashboard available at: http://localhost:8501")
    app.run(port=8501, debug=True)
