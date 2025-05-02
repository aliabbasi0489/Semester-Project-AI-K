from flask import Flask, jsonify, request, render_template
from flask_talisman import Talisman
import base64
import os
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes




# Load environment variables
load_dotenv()

app = Flask(__name__, 
    static_folder='static',
    template_folder='templates')

# Configure Talisman for security headers
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        "'unsafe-inline'"
    ],
    'style-src': [
        "'self'",
        'https://cdn.tailwindcss.com',
        'https://cdnjs.cloudflare.com',
        "'unsafe-inline'"
    ],
    'font-src': [
        "'self'",
        'https://cdnjs.cloudflare.com'
    ],
    'img-src': "'self' data:"
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=None,
    force_https=False,
    strict_transport_security=False
)

class PQCrypto:
    @staticmethod
    def generate_keypair():
        # For a real post-quantum implementation, you would use a proper PQ algorithm
        # This is just a simplified simulation using AES
        private_key = get_random_bytes(32)
        public_key = SHA3_256.new(private_key).digest()
        return public_key, private_key

    @staticmethod
    def encrypt(public_key, message):
        # For simplicity, we're using the public key directly as the AES key
        # In a real PQ crypto system, this would be handled differently
        key = public_key[:32]
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return ciphertext, cipher.nonce, tag

    @staticmethod
    def decrypt(private_key, ciphertext, nonce, tag):
        # For proper post-quantum crypto, this would use the private key differently
        # In our simplified model, we need to derive the same key used for encryption
        # We'll use the SHA3-256 hash of the private key to simulate deriving the public key
        key = SHA3_256.new(private_key).digest()[:32]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    try:
        public_key, private_key = PQCrypto.generate_keypair()
        return jsonify({
            'status': 'success',
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'private_key': base64.b64encode(private_key).decode('utf-8'),
            'algorithm': 'PQC-AES-SIMULATION'
        })
    except Exception as e:
        app.logger.error(f"Error generating keys: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate keys'
        }), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    try:
        data = request.json
        if not data or 'public_key' not in data or 'message' not in data:
            return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400

        public_key = base64.b64decode(data['public_key'])
        message = data['message'].encode('utf-8')
        
        # Log encryption details
        app.logger.debug(f"Encryption - Public key length: {len(public_key)}")
        app.logger.debug(f"Encryption - Message length: {len(message)}")
        
        # Use PQCrypto class for encryption
        ciphertext, nonce, tag = PQCrypto.encrypt(public_key, message)

        return jsonify({
            'status': 'success',
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'encrypted_message': base64.b64encode(ciphertext).decode('utf-8')  # For display
        })
    except Exception as e:
        app.logger.error(f"Encryption error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        app.logger.debug(f"Received decrypt request: {data.keys()}")
        
        # Validate all required fields exist
        required_fields = ['ciphertext', 'private_key', 'nonce', 'tag']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Decode all parameters with error handling
        try:
            ciphertext = base64.b64decode(data['ciphertext'])
            private_key = base64.b64decode(data['private_key'])
            nonce = base64.b64decode(data['nonce'])
            tag = base64.b64decode(data['tag'])
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Base64 decoding failed: {str(e)}'
            }), 400

        # Log decryption details
        app.logger.debug(f"Decryption - Private key length: {len(private_key)}")
        app.logger.debug(f"Decryption - Ciphertext length: {len(ciphertext)}")
        app.logger.debug(f"Decryption - Nonce length: {len(nonce)}")
        app.logger.debug(f"Decryption - Tag length: {len(tag)}")

        # Perform decryption using PQCrypto class
        try:
            decrypted = PQCrypto.decrypt(private_key, ciphertext, nonce, tag)
            
            return jsonify({
                'status': 'success',
                'message': decrypted.decode('utf-8')
            })
        except ValueError as e:
            app.logger.error(f"Decryption failed: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Decryption failed - possible corrupted data or wrong key'
            }), 400
        except Exception as e:
            app.logger.error(f"Unexpected decryption error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to decrypt message'
            }), 500

    except Exception as e:
        app.logger.error(f"Server error during decryption: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500


if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    ssl_context = None
    
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        ssl_context = ('cert.pem', 'key.pem')
    
    app.run(
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 5000)),
        debug=debug_mode,
        ssl_context=ssl_context
    )
  
