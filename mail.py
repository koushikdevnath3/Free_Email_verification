from flask import Flask, request, jsonify,render_template
import dns.resolver
import smtplib

app = Flask(__name__)

def verify_email_domain(email):
    # Extract domain from email address
    domain = email.split('@')[1]

    # Perform DNS MX record check
    try:
        mx_records = dns.resolver.query(domain, 'MX')
        return True
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.Timeout:
        return False

def verify_email_spf(email):
    # Extract domain from email address
    domain = email.split('@')[1]

    # Perform DNS SPF record check
    try:
        txt_records = dns.resolver.query(domain, 'TXT')
        for record in txt_records:
            if 'v=spf1' in record.to_text():
                return True
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.Timeout:
        return False

def verify_email_smtp(email):
    # Attempt to establish SMTP connection and send test email
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.query(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        server = smtplib.SMTP(mx_record)
        server.connect(mx_record)
        server.helo()
        server.mail('example@example.com')
        code, _ = server.rcpt(str(email))
        server.quit()
        if code == 250:
            return True
        else:
            return False
    except smtplib.SMTPConnectError:
        return False
    except smtplib.SMTPServerDisconnected:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.exception.Timeout:
        return False

def verify_email(email):
    # Check if email address has valid syntax
    if '@' not in email or email.count('@') > 1:
        return False

    # Verify email domain and SPF record
    if verify_email_domain(email) and verify_email_spf(email):
        # Verify email address using SMTP
        return verify_email_smtp(email)
    else:
        return False

@app.route('/verify_email', methods=['POST'])
def verify_email_route():
    email = request.form['email']
    result = verify_email(email)
    if result:
        return jsonify({'valid': True, 'message': 'The email address is valid.'})
    else:
        return jsonify({'valid': False, 'message': 'The email address is not valid.'})

@app.route('/', methods=['GET'])
def home():
    return render_template('Email.html')


if __name__ == '__main__':
    app.run(debug=True)
