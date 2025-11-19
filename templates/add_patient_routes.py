# Add the following routes to your main app file (e.g. /home/victor/Project/app.py).
# You can append this file to your app.py or copy-paste the contents into it.

import os
import sqlite3
from flask import request, redirect, url_for, flash, render_template, current_app
from werkzeug.utils import secure_filename

# Configuration (will use the same data.db and uploads folder as the templates)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(os.path.dirname(BASE_DIR), 'data.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(BASE_DIR), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def _get_db_conn():
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Patient detail page (works with numeric or UUID string ids)
@app.route('/patient/<patient_id>')
def patient_detail(patient_id):
    conn = _get_db_conn()
    patient = None
    uploads = []
    if conn:
        cur = conn.execute('SELECT id, name, email, phone, created_at FROM patients WHERE id = ?', (patient_id,))
        row = cur.fetchone()
        if row:
            patient = dict(row)
        cur = conn.execute('SELECT * FROM uploads WHERE patient_id = ? ORDER BY uploaded_at DESC', (patient_id,))
        uploads = [dict(r) for r in cur.fetchall()]
        conn.close()

    if not patient:
        flash('Patient not found')
        return redirect(url_for('index'))

    return render_template('patient_detail.html', patient=patient, uploads=uploads)


# Delete upload (marks status deleted, records who deleted and logs the action)
@app.route('/upload/delete/<upload_id>', methods=['POST'])
def upload_delete(upload_id):
    deleted_by = request.form.get('deleted_by') or request.args.get('deleted_by') or 'admin'
    conn = _get_db_conn()
    if not conn:
        flash('Database not available')
        return redirect(request.referrer or url_for('admin_uploads'))

    conn.execute('UPDATE uploads SET status = ?, deleted_by = ?, deleted_at = CURRENT_TIMESTAMP WHERE id = ?', ('deleted', deleted_by, upload_id))
    conn.execute('INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)', (deleted_by, 'delete_upload', f'upload_id={upload_id}'))
    conn.commit()
    conn.close()

    flash(f'Upload {upload_id} marked deleted by {deleted_by}')
    return redirect(request.referrer or url_for('admin_uploads'))


# Upload result handler (POST). If your app already has an upload handler, skip this.
@app.route('/upload/<patient_id>', methods=['POST'])
def upload_result_for_patient_handler(patient_id):
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.referrer or url_for('index'))
    f = request.files['file']
    if f.filename == '':
        flash('No selected file')
        return redirect(request.referrer or url_for('index'))

    filename = secure_filename(f.filename)
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    f.save(save_path)

    conn = _get_db_conn()
    if conn:
        conn.execute('INSERT INTO uploads (patient_id, filename, uploaded_by, status) VALUES (?, ?, ?, ?)', (patient_id, filename, 'web', 'active'))
        conn.commit()
        conn.close()

    flash('Result uploaded')
    return redirect(url_for('admin_uploads'))
