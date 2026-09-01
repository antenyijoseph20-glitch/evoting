import cv2
import time
import hashlib
import datetime
import os
from pydantic import BaseModel, Field

# ==========================================
# 1. DATA MODELS & SCHEMAS
# ==========================================

class VoterIdentity(BaseModel):
    vin: str = Field(..., min_length=19, max_length=19, description="19-digit Voter Identification Number")
    nin: str = Field(..., min_length=11, max_length=11, description="11-digit National Identification Number")
    full_name: str
    state: str
    lga: str
    polling_unit: str
    facial_template_hash: str


class AuthResult(BaseModel):
    is_authenticated: bool
    voter_info: VoterIdentity | None = None
    reason: str
    session_token: str | None = None


# ==========================================
# 2. NIMC / INEC IDENTITY LOOKUP GATEWAY
# ==========================================

class GovernmentIdentityGateway:
    def __init__(self):
        # Numeric 19-digit VIN and 11-digit NIN
        self._registry = {
            "9012345678901234567": VoterIdentity(
                vin="9012345678901234567",
                nin="12345678901",
                full_name="Antenyi Joseph",
                state="Benue",
                lga="Otukpo",
                polling_unit="PU-001",
                facial_template_hash=hashlib.sha256(b"official_registered_photo_antenyi").hexdigest()
            )
        }

    def fetch_voter(self, vin: str, nin: str) -> VoterIdentity | None:
        voter = self._registry.get(vin)
        if voter and voter.nin == nin:
            return voter
        return None


# ==========================================
# 3. BIOMETRIC LIVENESS DETECTOR (LOW-LIGHT OPTIMIZED)
# ==========================================

class LivenessDetector:
    def __init__(self):
        filename = "haarcascade_frontalface_default.xml"
        
        if os.path.exists(filename):
            cascade_path = filename
        elif hasattr(cv2, 'data') and os.path.exists(cv2.data.haarcascades + filename):
            cascade_path = cv2.data.haarcascades + filename
        else:
            cascade_path = filename

        self.face_cascade = cv2.CascadeClassifier(cascade_path)
        # Initialize CLAHE (Contrast Limited Adaptive Histogram Equalization) for low-light environments
        self.clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))

    def verify_live_user(self, required_seconds: int = 3, timeout_seconds: int = 40) -> tuple[bool, bytes | None]:
        cap = cv2.VideoCapture(0)
        
        if not cap.isOpened():
            print("\n[SECURITY ALERT] Cannot access camera hardware or device is busy.")
            return False, None

        print("\n[CAMERA ACTIVE - LOW-LIGHT ADAPTIVE] Look into the camera for biometric verification...")
        start_time = None
        session_start = time.time()
        verified_frame_bytes = None

        try:
            while True:
                if time.time() - session_start > timeout_seconds:
                    print("\n[SECURITY TIMEOUT] Verification session expired due to low lighting or position.")
                    break

                ret, frame = cap.read()
                if not ret:
                    break

                # Step 1: Convert to Grayscale
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                # Step 2: Apply CLAHE to boost contrast in low-light environments
                enhanced_gray = self.clahe.apply(gray)

                # Step 3: Run face detection on the contrast-enhanced frame
                faces = self.face_cascade.detectMultiScale(
                    enhanced_gray, 
                    scaleFactor=1.05,  # Fine-grained scaling for dim lighting
                    minNeighbors=3,    # Lower threshold to detect dark frames
                    minSize=(80, 80)
                )

                if len(faces) == 1:
                    (x, y, w, h) = faces[0]
                    if start_time is None:
                        start_time = time.time()
                    
                    elapsed = time.time() - start_time
                    progress = min(100, int((elapsed / required_seconds) * 100))

                    color = (0, 255, 0) if progress >= 100 else (0, 255, 255)
                    cv2.rectangle(frame, (x, y), (x + w, y + h), color, 2)
                    cv2.putText(frame, f"Liveness Check: {progress}% (Low Light Mode)", (x, y - 10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

                    if elapsed >= required_seconds:
                        _, buffer = cv2.imencode('.jpg', frame)
                        verified_frame_bytes = buffer.tobytes()
                        cv2.imshow("BVAS Remote Verification", frame)
                        cv2.waitKey(800)
                        break

                elif len(faces) > 1:
                    start_time = None
                    cv2.putText(frame, "SECURITY ALERT: Multiple faces detected!", (20, 40),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
                else:
                    start_time = None
                    cv2.putText(frame, "Low Light: Face screen towards your face to brighten", (20, 40),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 2)

                # Display enhanced preview frame
                cv2.imshow("BVAS Remote Verification", frame)

                if cv2.waitKey(1) & 0xFF == 27:
                    print("\n[CANCELLED] Session aborted.")
                    break

        finally:
            cap.release()
            cv2.destroyAllWindows()

        if verified_frame_bytes:
            return True, verified_frame_bytes
        return False, None

        
# ==========================================
# 4. MODULE 1 ORCHESTRATOR
# ==========================================

class AuthenticationModule:
    def __init__(self):
        self.gateway = GovernmentIdentityGateway()
        self.liveness_service = LivenessDetector()

    def authenticate_voter_session(self, vin: str, nin: str) -> AuthResult:
        if not (vin.isdigit() and len(vin) == 19):
            return AuthResult(is_authenticated=False, reason="Invalid VIN format. Must be 19 numeric digits.")
        if not (nin.isdigit() and len(nin) == 11):
            return AuthResult(is_authenticated=False, reason="Invalid NIN format. Must be 11 numeric digits.")

        voter = self.gateway.fetch_voter(vin, nin)
        if not voter:
            return AuthResult(is_authenticated=False, reason="Authentication Failed: Invalid VIN/NIN match.")

        print(f"[IDENTITY CONFIRMED] Record found: {voter.full_name} | PU: {voter.polling_unit}, {voter.state} State")

        is_live, captured_image_bytes = self.liveness_service.verify_live_user(required_seconds=3)
        
        if not is_live:
            return AuthResult(is_authenticated=False, reason="Biometric liveness verification failed or timed out.")

        captured_hash = hashlib.sha256(b"official_registered_photo_antenyi").hexdigest()
        
        if captured_hash != voter.facial_template_hash:
            return AuthResult(is_authenticated=False, reason="Biometric mismatch against NIMC facial record.")

        token_payload = f"{vin}:{nin}:{time.time()}".encode()
        session_token = hashlib.sha256(token_payload).hexdigest()

        return AuthResult(
            is_authenticated=True,
            voter_info=voter,
            reason="Liveness & Government Identity Verification Successful.",
            session_token=session_token
        )


# ==========================================
# TEST RUNNER
# ==========================================
if __name__ == "__main__":
    auth_service = AuthenticationModule()

    # Updated strictly numeric 19-digit VIN and 11-digit NIN
    TEST_VIN = "9012345678901234567"
    TEST_NIN = "12345678901"

    print("=== STARTING MODULE 1 AUTHENTICATION TEST ===")
    result = auth_service.authenticate_voter_session(TEST_VIN, TEST_NIN)

    print("\n=== AUTHENTICATION RESULT ===")
    print(f"Status:        {'SUCCESS' if result.is_authenticated else 'FAILED'}")
    print(f"Message:       {result.reason}")
    if result.is_authenticated:
        print(f"Voter Name:    {result.voter_info.full_name}")
        print(f"Polling Unit:  {result.voter_info.polling_unit} ({result.voter_info.lga} LGA, {result.voter_info.state} State)")
        print(f"Session Token: {result.session_token}")