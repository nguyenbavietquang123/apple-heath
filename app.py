import os
import requests
import jwt  # pip install pyjwt
from flask import Flask, render_template_string, request, redirect, session, url_for, jsonify
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")  # Secure session key

# --- CONFIGURATION & CONSTANTS ---

# List of resources that require Patient ID filtering
PATIENT_RESOURCES = [
    "Patient", "AllergyIntolerance", "CarePlan", "CareTeam", "Condition",
    "Coverage", "Device", "DiagnosticReport", "DocumentReference", "Encounter",
    "Goal", "Immunization", "MedicationDispense", "MedicationRequest",
    "Observation", "Procedure", "Provenance", "QuestionnaireResponse",
    "RelatedPerson", "ServiceRequest"
]

# List of resources to search without Patient ID (System level)
SYSTEM_RESOURCES = [
    "Location", "Medication", "Organization", "Practitioner", "PractitionerRole"
]

# --- TEMPLATES ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Apple health</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding: 20px; background-color: #f8f9fa; }
        .card { margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .status-badge { font-weight: bold; width: 60px; display: inline-block; text-align: center; }
        .details-box { display: none; margin-top: 10px; background: #eee; padding: 10px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; font-size: 0.85em; }
    </style>
</head>
<body>

<div class="container">
    <h2 class="mb-4 text-primary">Apple Health</h2>

    {% if not session.get('access_token') %}
    <div class="card">
        <div class="card-header bg-dark text-white">App Configuration</div>
        <div class="card-body">
            <form action="/login" method="POST">
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label>FHIR Base URL</label>
                        <input type="text" name="fhir_url" class="form-control" placeholder="https://hapi.fhir.org/baseR4" required value="{{ session.get('config', {}).get('fhir_url', '') }}">
                    </div>
                    <div class="col-md-6 mb-3">
                        <label>Auth Endpoint</label>
                        <input type="text" name="auth_url" class="form-control" placeholder="https://keycloak.../auth" required value="{{ session.get('config', {}).get('auth_url', '') }}">
                    </div>
                    <div class="col-md-6 mb-3">
                        <label>Token Endpoint</label>
                        <input type="text" name="token_url" class="form-control" placeholder="https://keycloak.../token" required value="{{ session.get('config', {}).get('token_url', '') }}">
                    </div>
                    <div class="col-md-3 mb-3">
                        <label>Client ID</label>
                        <input type="text" name="client_id" class="form-control" required value="{{ session.get('config', {}).get('client_id', '') }}">
                    </div>
                    <div class="col-md-3 mb-3">
                        <label>Client Secret</label>
                        <input type="password" name="client_secret" class="form-control" required value="{{ session.get('config', {}).get('client_secret', '') }}">
                    </div>
                </div>
                <button type="submit" class="btn btn-primary w-100">Go to app</button>
            </form>
        </div>
    </div>
    {% else %}
    
    <div class="card">
        <div class="card-body">
            <div class="alert alert-success d-flex justify-content-between align-items-center">
                <span><strong>Connected!</strong> Patient ID: <code>{{ patient_id }}</code></span>
                <a href="/logout" class="btn btn-sm btn-outline-danger">Reset / Logout</a>
            </div>
            <button onclick="runTests()" id="runBtn" class="btn btn-success w-100">Access FHIR data</button>
        </div>
    </div>

    <div id="resultsArea"></div>

    {% endif %}
</div>

<script>
async function runTests() {
    const btn = document.getElementById('runBtn');
    const area = document.getElementById('resultsArea');
    btn.disabled = true;
    btn.innerText = "Running Tests...";
    area.innerHTML = "";

    try {
        const response = await fetch('/run_tests');
        const data = await response.json();
        
        // --- FIX: Logic to handle redirect ---
        if (data.redirect) {
            console.log("Redirecting to:", data.redirect);
            window.location.href = data.redirect;
            return;
        }

        let html = "";
        data.results.forEach((res, index) => {
            let color = res.status >= 200 && res.status < 300 ? 'success' : 'danger';
            let resourceName = res.resource;
            
            html += `
            <div class="card">
                <div class="card-body py-2">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="badge bg-${color} status-badge">${res.status}</span>
                            <span class="fw-bold ms-2">${resourceName}</span>
                            <span class="text-muted ms-2" style="font-size:0.8em">(${res.url})</span>
                        </div>
                        <button class="btn btn-sm btn-outline-secondary" onclick="toggleDetails(${index})">Response Message</button>
                    </div>
                    <div id="detail-${index}" class="details-box">
                        <strong>Error/Body:</strong> ${res.body}
                    </div>
                </div>
            </div>`;
        });
        area.innerHTML = html;
    } catch (e) {
        area.innerHTML = `<div class="alert alert-danger">Application Error: ${e}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerText = "Run Whitebox Tests";
    }
}

function toggleDetails(id) {
    var x = document.getElementById("detail-" + id);
    if (x.style.display === "none" || x.style.display === "") {
        x.style.display = "block";
    } else {
        x.style.display = "none";
    }
}
</script>
</body>
</html>
"""

# --- ROUTES ---

@app.route('/')
def index():
    pid = session.get('patient_id', 'Unknown')
    return render_template_string(HTML_TEMPLATE, patient_id=pid)

@app.route('/login', methods=['POST'])
def login():
    # Store config in session
    session['config'] = {
        'fhir_url': request.form['fhir_url'].rstrip('/'),
        'auth_url': request.form['auth_url'],
        'token_url': request.form['token_url'],
        'client_id': request.form['client_id'],
        'client_secret': request.form['client_secret']
    }
    
    # Generate Authorization Code Flow URL
    # Same scopes as defined in your requirement
    scopes = "launch/patient openid fhirUser offline_access patient/Patient.rs patient/AllergyIntolerance.rs patient/CarePlan.rs patient/CareTeam.rs patient/Condition.rs patient/Coverage.rs patient/Device.rs patient/DiagnosticReport.rs patient/DocumentReference.rs patient/Encounter.rs patient/Goal.rs patient/Immunization.rs patient/Location.rs patient/Medication.rs patient/MedicationDispense.rs patient/MedicationRequest.rs patient/Observation.rs patient/Organization.rs patient/Practitioner.rs patient/PractitionerRole.rs patient/Procedure.rs patient/Provenance.rs patient/QuestionnaireResponse.rs patient/RelatedPerson.rs patient/ServiceRequest.rs patient/Specimen.rs"
    
    params = {
        "response_type": "code",
        "client_id": request.form['client_id'],
        "redirect_uri": url_for('callback', _external=True),
        "scope": scopes
    }
    auth_redirect = f"{request.form['auth_url']}?{urlencode(params)}"
    return redirect(auth_redirect)

# --- NEW: Re-Auth Route to handle 405 fix ---
@app.route('/reauth')
def reauth():
    """
    Called when Refresh Token fails. 
    Uses stored config to redirect to Keycloak immediately via GET.
    """
    cfg = session.get('config')
    
    # If no config (session dead), go to home to fill form
    if not cfg:
        return redirect(url_for('index'))
        
    # Re-use the same scopes
    scopes = "launch/patient openid fhirUser offline_access patient/Patient.rs patient/AllergyIntolerance.rs patient/CarePlan.rs patient/CareTeam.rs patient/Condition.rs patient/Coverage.rs patient/Device.rs patient/DiagnosticReport.rs patient/DocumentReference.rs patient/Encounter.rs patient/Goal.rs patient/Immunization.rs patient/Location.rs patient/Medication.rs patient/MedicationDispense.rs patient/MedicationRequest.rs patient/Observation.rs patient/Organization.rs patient/Practitioner.rs patient/PractitionerRole.rs patient/Procedure.rs patient/Provenance.rs patient/QuestionnaireResponse.rs patient/RelatedPerson.rs patient/ServiceRequest.rs patient/Specimen.rs"

    params = {
        "response_type": "code",
        "client_id": cfg['client_id'],
        "redirect_uri": url_for('callback', _external=True),
        "scope": scopes
    }
    auth_redirect = f"{cfg['auth_url']}?{urlencode(params)}"
    return redirect(auth_redirect)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code returned from Auth server"
    
    cfg = session.get('config')
    
    # Exchange code for token
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": url_for('callback', _external=True),
        "client_id": cfg['client_id'],
        "client_secret": cfg['client_secret']
    }
    
    try:
        r = requests.post(cfg['token_url'], data=payload)
        r.raise_for_status()
        tokens = r.json()
        
        session['access_token'] = tokens.get('access_token')
        session['refresh_token'] = tokens.get('refresh_token')
        
        try:
            decoded = jwt.decode(session['access_token'], options={"verify_signature": False})
            session['patient_id'] = decoded.get('patient_id') or decoded.get('sub') 
        except Exception as e:
            session['patient_id'] = "Error-Parsing-Token"

    except Exception as e:
        return f"Token Exchange Failed: {str(e)} - Body: {r.text if 'r' in locals() else ''}"
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- CORE LOGIC ---

def refresh_access_token():
    cfg = session.get('config')
    refresh_token = session.get('refresh_token')
    
    if not refresh_token:
        return False

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": cfg['client_id'],
        "client_secret": cfg['client_secret']
    }
    
    try:
        r = requests.post(cfg['token_url'], data=payload)
        if r.status_code == 200:
            tokens = r.json()
            session['access_token'] = tokens.get('access_token')
            if tokens.get('refresh_token'):
                session['refresh_token'] = tokens.get('refresh_token')
            return True
        else:
            return False
    except:
        return False

def make_fhir_request(method, url, params=None):
    access_token = session.get('access_token')
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    
    try:
        if method == 'GET':
            resp = requests.get(url, headers=headers, params=params)
        
        if resp.status_code == 401:
            if "HAPI-0644" in resp.text:
                print("Received HAPI-0644 401. Attempting Refresh...")
                if refresh_access_token():
                    headers["Authorization"] = f"Bearer {session.get('access_token')}"
                    if method == 'GET':
                        resp = requests.get(url, headers=headers, params=params)
                else:
                    # Refresh failed, signal redirect
                    return {"status": 401, "body": "Refresh Token Expired.", "redirect": True}
            else:
                pass

        return {"status": resp.status_code, "body": resp.text[:500]}
        
    except Exception as e:
        return {"status": 0, "body": str(e)}

@app.route('/run_tests')
def run_tests():
    if not session.get('access_token'):
        # If no token at all, go to reauth to check config
        return jsonify({"redirect": url_for('reauth')})
    
    fhir_base = session['config']['fhir_url']
    patient_id = session.get('patient_id')
    
    results = []
    
    # 1. Test Patient-Scoped Resources
    for resource in PATIENT_RESOURCES:
        target_url = f"{fhir_base}/{resource}"
        params = {}
        if resource == "Patient":
            params = {"_id": patient_id}
        else:
            params = {"patient": patient_id}
            
        res = make_fhir_request("GET", target_url, params)
        
        # --- FIX: Use reauth route instead of login ---
        if res.get("redirect"):
             return jsonify({"redirect": url_for('reauth')}) 

        results.append({
            "resource": "Read:" + resource,
            "status": res['status'],
            "url": f"{target_url}?{urlencode(params)}",
            "body": res['body']
        })
    for resource in PATIENT_RESOURCES:
        target_url = f"{fhir_base}/{resource}"
        res = make_fhir_request("GET", target_url)
        
        # --- FIX: Use reauth route instead of login ---
        if res.get("redirect"):
             return jsonify({"redirect": url_for('reauth')})

        results.append({
            "resource": "Search:" + resource,
            "status": res['status'],
            "url": target_url,
            "body": res['body']
        })

    # 2. Test System-Scoped Resources
    for resource in SYSTEM_RESOURCES:
        target_url = f"{fhir_base}/{resource}"
        res = make_fhir_request("GET", target_url)
        
        # --- FIX: Use reauth route instead of login ---
        if res.get("redirect"):
             return jsonify({"redirect": url_for('reauth')})

        results.append({
            "resource": "Search:" + resource,
            "status": res['status'],
            "url": target_url,
            "body": res['body']
        })

    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(debug=True)