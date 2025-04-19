from flask import Flask, render_template, flash, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from database.models import db, Usuario

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:NtCn45_67()#$@localhost/mi_academia'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'DFDSFSD'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gutierrezpedrojose021@gmail.com'
app.config['MAIL_PASSWORD'] = 'akxc mzde aczi qssu'
app.config['MAIL_DEFAULT_SENDER'] = 'gutierrezpedrojose021@gmail.com'

mail = Mail(app)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'Login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@app.route('/')
def Index():
    return render_template('index.html')

@app.route('/aboutus')
def AboutUs():
    return render_template('aboutus.html')

@app.route('/courses')
def Courses():
    return render_template('courses.html')

@app.route('/teachers')
def Teachers():
    return render_template('teachers.html')

@app.route('/contact', methods=['GET', 'POST'])
def Contact():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        asunto = request.form['asunto']
        mensaje = request.form['mensaje']

        msg = Message(asunto,
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=['gutierrezpedrojose021@gmail.com'])
        msg.reply_to = email  # Para que puedas darle "responder" al email del remitente
        msg.body = f"Nombre: {nombre}\nEmail: {email}\n\nMensaje:\n{mensaje}"
        mail.send(msg)

        flash('Tu mensaje ha sido enviado con éxito.', 'success')
        return redirect(url_for('Contact'))

    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        usuario = Usuario.query.filter_by(email=email).first()

        if usuario:
            if check_password_hash(usuario.password, password):
                login_user(usuario)
                return redirect(url_for('Perfil'))
            else:
                flash('Contraseña incorrecta', 'danger')
                return redirect(url_for('Login'))
        else:
            flash('Correo electrónico no registrado', 'danger')
            return redirect(url_for('Login'))

    return render_template('login.html')

@app.route('/perfil')
@login_required
def Perfil():
    return render_template('perfil.html', usuario=current_user)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def Logout():
    logout_user()
    return redirect(url_for('Login'))

@app.route('/events')
@login_required
def Events():
    return render_template('events.html')

@app.route('/prices')
@login_required
def Prices():
    return render_template('prices.html')

@app.route('/coursesv2')
@login_required
def CoursesV2():
    return render_template('coursesv2.html')

@app.route('/register', methods=['GET', 'POST'])
def Register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        telefono = request.form['telefono']
        password = request.form['password']
        confirmar_password = request.form['confirmar_password']

        if password != confirmar_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('Register'))
        
        usuario_existente_username = Usuario.query.filter_by(username=username).first()
        if usuario_existente_username:
            flash('Ese nombre de usuario ya está en uso.', 'danger')
            return redirect(url_for('Register'))

        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('El correo ya está registrado. Usa otro.', 'danger')
            return redirect(url_for('Register'))

        nuevo_usuario = Usuario(
            username=username,
            email=email,
            telefono=telefono,
            password=generate_password_hash(password)
        )
        
        # Guardar con manejo de errores
        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash('Registro exitoso. ¡Ya puedes iniciar sesión!', 'success')
            return redirect(url_for('Login'))
        except Exception as e:
            db.session.rollback()
            flash('Ocurrió un error al guardar en la base de datos.', 'danger')
            print(f"Error al registrar usuario: {e}")  # O usa logging si prefieres
    
    return render_template('register.html')



if __name__ == '__main__':
    app.run(port=4000)