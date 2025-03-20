from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from db import get_db_connection
import bcrypt
import config
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room  # ✅ Используем Flask-SocketIO

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = config.JWT_SECRET
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app, supports_credentials=True)


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    name = data.get("name")
    password = data.get("password")
    city = data.get("city")
    categories = data.get("categories")  # Expecting list of category IDs

    if not email or not name or not password or not city or not categories:
        return jsonify({"error": "All fields, including city and categories, are required"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = None  

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Insert the user and retrieve the user ID
            cursor.execute(
                "INSERT INTO users (id, email, name, password_hash, city) VALUES (UUID(), %s, %s, %s, %s)",
                (email, name, hashed_password, city),
            )
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"error": "User registration failed"}), 500
            user_id = user["id"]

            # Insert user categories
            for category_id in categories:
                cursor.execute(
                    "INSERT INTO user_categories (user_id, category_id) VALUES (%s, %s)",
                    (user_id, category_id),
                )

        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/categories", methods=["GET"])
def get_categories():
    lang = request.args.get("lang", "en")  # По умолчанию английский
    if lang not in ["en", "cs"]:
        return jsonify({"error": "Invalid language parameter. Use 'en' or 'cz'"}), 400

    column_name = "en_name" if lang == "en" else "cz_name"

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT id, {column_name} AS name FROM categories")
            categories = cursor.fetchall()

        return jsonify(categories), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()



@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = None  

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, email, name, city FROM users WHERE email = %s", (email,)
            )
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "Invalid email or password"}), 401

            cursor.execute("SELECT password_hash FROM users WHERE email = %s", (email,))
            password_hash = cursor.fetchone()

            if password_hash and bcrypt.checkpw(password.encode("utf-8"), password_hash["password_hash"].encode("utf-8")):
                access_token = create_access_token(identity=user["id"], expires_delta=None)

                # Получаем категории пользователя
                cursor.execute(
                    """
                    SELECT c.id, c.en_name, c.cz_name 
                    FROM user_categories uc
                    JOIN categories c ON uc.category_id = c.id
                    WHERE uc.user_id = %s
                    """,
                    (user["id"],)
                )
                categories = cursor.fetchall()

                return jsonify({
                    "access_token": access_token,
                    "user": {
                        "id": user["id"],
                        "email": user["email"],
                        "name": user["name"],
                        "city": user["city"],
                        "categories": categories
                    }
                }), 200
            else:
                return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route("/profile", methods=["GET", "PUT"])
@jwt_required()
def user_profile():
    user_id = get_jwt_identity()  # Получаем ID текущего пользователя

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:  
            if request.method == "GET":
                # 🔹 Получаем данные пользователя
                cursor.execute(
                    "SELECT id, email, name, city FROM users WHERE id = %s",
                    (user_id,)
                )
                user = cursor.fetchone()

                if not user:
                    return jsonify({"error": "User not found"}), 404

                # 🔹 Получаем категории пользователя
                cursor.execute(
                    """
                    SELECT c.id, c.en_name, c.cz_name 
                    FROM user_categories uc
                    JOIN categories c ON uc.category_id = c.id
                    WHERE uc.user_id = %s
                    """,
                    (user_id,)
                )
                categories = cursor.fetchall()

                user["categories"] = categories  # Добавляем категории к профилю
                return jsonify(user), 200

            elif request.method == "PUT":
                data = request.json
                name = data.get("name")
                city = data.get("city")
                category_ids = data.get("categories", [])

                if not name or not city:
                    return jsonify({"error": "Name and city are required"}), 400

                # 🔹 Обновляем имя и город пользователя
                cursor.execute(
                    "UPDATE users SET name = %s, city = %s WHERE id = %s",
                    (name, city, user_id)
                )

                # 🔹 Обновляем категории пользователя (удаляем старые, добавляем новые)
                cursor.execute("DELETE FROM user_categories WHERE user_id = %s", (user_id,))
                for category_id in category_ids:
                    cursor.execute(
                        "INSERT INTO user_categories (user_id, category_id) VALUES (%s, %s)",
                        (user_id, category_id)
                    )

                conn.commit()

                return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/events", methods=["POST"])
@jwt_required()
def create_event():
    data = request.json
    title = data.get("title")
    description = data.get("description")
    date_time = data.get("date_time")
    city = data.get("city")
    location = data.get("location")  # Ожидаем формат "lat,lng"
    
    user_id = get_jwt_identity()  # Получаем ID текущего пользователя

    if not title or not date_time or not city or not location:
        return jsonify({"error": "Title, date, city, and location are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO events (id, title, description, date_time, city, location, created_by)
                VALUES (UUID(), %s, %s, %s, %s, %s, %s)
                """,
                (title, description, date_time, city, location, user_id),
            )
        conn.commit()
        return jsonify({"message": "Event created successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/events", methods=["GET"])
@jwt_required() 
def get_events():
    city = request.args.get("city", None)
    filter_by_user = request.args.get("filter_by_user", "false").lower() == "true"
    categories = request.args.getlist("categories")  # Получаем список категорий
    show_finished = request.args.get("show_finished", "false").lower() == "true"
    user_id = get_jwt_identity()  # Получаем ID текущего пользователя, если авторизован

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            query = """
                SELECT DISTINCT e.id, e.title, e.description, e.date_time, e.city, e.location
                FROM events e
                LEFT JOIN participants p ON e.id = p.event_id
                LEFT JOIN event_categories ec ON e.id = ec.event_id
            """
            conditions = []
            params = []

            # Фильтр по пользователю (если включено)
            if filter_by_user and user_id:
                conditions.append("(e.created_by = %s OR p.user_id = %s)")
                params.extend([user_id, user_id])

            # Фильтр по городу
            if city:
                conditions.append("e.city = %s")
                params.append(city)

            # Фильтр по категориям
            if categories:
                conditions.append("ec.category_id IN %s")
                params.append(tuple(categories))  # Используем кортеж для IN()

            # Фильтр по дате (если show_finished=False, то возвращаем только будущие события)
            if not show_finished:
                conditions.append("e.date_time >= %s")
                params.append(datetime.utcnow())
            # Добавляем условия в SQL-запрос
            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            cursor.execute(query, params)
            events = cursor.fetchall()

        return jsonify(events), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route("/events/<event_id>", methods=["GET"])
@jwt_required(optional=True)
def get_event(event_id):
    print(f"Fetching event with ID: {event_id}")  # Логируем запрос

    conn = get_db_connection()
    with conn.cursor() as cursor:
        # Получаем информацию о событии
        cursor.execute(
            """
            SELECT e.id, e.title, e.description, e.date_time, e.city, e.location, 
                   u.id AS created_by_id, u.name AS created_by_name
            FROM events e
            JOIN users u ON e.created_by = u.id
            WHERE e.id = %s
            """,
            (event_id,)
        )
        event = cursor.fetchone()

        if not event:
            print("Event not found!")
            return jsonify({"error": "Event not found"}), 404

        print(f"Event raw data: {event}")  # Логируем сырые данные


        cursor.execute(
            """
            SELECT u.id, u.name, u.email, p.status
            FROM participants p
            JOIN users u ON p.user_id = u.id
            WHERE p.event_id = %s
            """,
            (event_id,)
        )
        participants = cursor.fetchall()
        # Формируем JSON-ответ без использования zip() и dict()
        event_data = {
            "id": event["id"],
            "title": event["title"],
            "description": event["description"],
            "date_time": event["date_time"],
            "city": event["city"],
            "location": event["location"],
            "created_by": {
                "id":event["created_by_id"],
                "name":event["created_by_name"]
            },
            "participants": participants
        }

    print(f"Final event data before returning: {event_data}")  # Логируем финальный объект
    return jsonify(event_data), 200



# 🔹 Проверка перед повторным присоединением
@app.route("/events/<event_id>/join", methods=["POST"])
@jwt_required()
def join_event(event_id):
    current_user_id = get_jwt_identity()

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Проверяем, был ли пользователь удален (статус `declined`)
            cursor.execute(
                "SELECT status FROM participants WHERE event_id = %s AND user_id = %s",
                (event_id, current_user_id)
            )
            participant = cursor.fetchone()

            if participant:
                if participant["status"] == "declined":
                    return jsonify({"error": "You have been removed from this event and cannot rejoin."}), 403
                if participant["status"] == "confirmed":
                    return jsonify({"error": "You are already a participant"}), 400

            # Добавляем или обновляем участника
            if participant:
                cursor.execute(
                    """
                    UPDATE participants 
                    SET status = 'confirmed' 
                    WHERE event_id = %s AND user_id = %s
                    """,
                    (event_id, current_user_id)
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO participants (event_id, user_id, status)
                    VALUES (%s, %s, 'confirmed')
                    """,
                    (event_id, current_user_id)
                )

            conn.commit()

        return jsonify({"message": "You have successfully joined the event"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route("/events/<event_id>/leave", methods=["DELETE"])
@jwt_required()
def leave_event(event_id):
    user_id = get_jwt_identity()  # Получаем ID текущего пользователя

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Проверяем статус участника
            cursor.execute(
                "SELECT status FROM participants WHERE user_id = %s AND event_id = %s",
                (user_id, event_id)
            )
            participant = cursor.fetchone()

            if not participant:
                return jsonify({"error": "User is not a participant of this event"}), 400

            if participant["status"] == "declined":
                return jsonify({"error": "You were removed from this event and cannot leave."}), 403

            # Удаляем пользователя из события
            cursor.execute(
                "DELETE FROM participants WHERE user_id = %s AND event_id = %s",
                (user_id, event_id)
            )

        conn.commit()
        return jsonify({"message": "Successfully left the event"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()


@app.route("/events/<event_id>/participants", methods=["GET"])
@jwt_required()
def get_event_participants(event_id):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT u.id, u.name, u.email,p.status
                FROM participants p
                JOIN users u ON p.user_id = u.id
                WHERE p.event_id = %s
                """,
                (event_id,)
            )
            participants = cursor.fetchall()

        return jsonify([
            {"id": p[0], "name": p[1], "email": p[2]} for p in participants
        ]), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()

@app.route("/events/<event_id>/remove/<user_id>", methods=["DELETE"])
@jwt_required()
def remove_participant(event_id, user_id):
    current_user_id = get_jwt_identity()

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 🔹 Проверяем, является ли текущий пользователь создателем события
            cursor.execute(
                "SELECT created_by FROM events WHERE id = %s",
                (event_id,)
            )
            event = cursor.fetchone()

            if not event:
                return jsonify({"error": "Event not found"}), 404

            if event["created_by"] != current_user_id:
                return jsonify({"error": "You are not authorized to remove participants"}), 403

            # 🔹 Проверяем, является ли `user_id` участником события
            cursor.execute(
                "SELECT user_id FROM participants WHERE event_id = %s AND user_id = %s",
                (event_id, user_id)
            )
            participant = cursor.fetchone()

            if not participant:
                return jsonify({"error": "User is not a participant"}), 400

            # 🔹 Обновляем статус участника на `declined`
            cursor.execute(
                """
                UPDATE participants 
                SET status = 'declined' 
                WHERE event_id = %s AND user_id = %s
                """,
                (event_id, user_id),
            )

            conn.commit()

            # 🔹 Получаем обновленный список участников (только `confirmed`)
            cursor.execute(
                """
                SELECT u.id, u.name, u.email 
                FROM participants p
                JOIN users u ON p.user_id = u.id
                WHERE p.event_id = %s AND p.status = 'confirmed'
                """,
                (event_id,),
            )
            updated_participants = cursor.fetchall()

        return jsonify({
            "message": "Participant removed successfully",
            "participants": updated_participants
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/events/<event_id>/chat", methods=["GET"])
@jwt_required()
def get_chat_messages(event_id):
    user_id = get_jwt_identity()

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Проверяем, является ли пользователь участником события
            cursor.execute(
                """
                SELECT e.created_by, p.user_id
                FROM events e
                LEFT JOIN participants p ON e.id = p.event_id AND p.user_id = %s
                WHERE e.id = %s
                """,
                (user_id, event_id)
            )
            result = cursor.fetchone()

            if not result or (result["user_id"] is None and result["created_by"] != user_id):
                return jsonify({"error": "You are not allowed to access this event's chat"}), 403

            # Получаем сообщения чата
            cursor.execute(
                """
                SELECT m.id, m.message, m.sent_at, u.id AS user_id, u.name 
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.event_id = %s ORDER BY m.sent_at ASC
                """,
                (event_id,)
            )
            messages = cursor.fetchall()

        return jsonify(messages), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

# 🔹 Отправка сообщения
@app.route("/events/<event_id>/chat", methods=["POST"])
@jwt_required()
def send_chat_message(event_id):
    user_id = get_jwt_identity()
    data = request.json
    message = data.get("message")

    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Проверяем, является ли пользователь участником события
            cursor.execute(
                """
                SELECT e.created_by, p.user_id
                FROM events e
                LEFT JOIN participants p ON e.id = p.event_id AND p.user_id = %s
                WHERE e.id = %s
                """,
                (user_id, event_id)
            )
            result = cursor.fetchone()

            if not result or (result["user_id"] is None and result["created_by"] != user_id):
                return jsonify({"error": "You are not allowed to access this event's chat"}), 403
            # Добавляем сообщение в базу данных
            cursor.execute(
                "INSERT INTO messages (event_id, user_id, message) VALUES (%s, %s, %s)",
                (event_id, user_id, message)
            )
            conn.commit()

            # Получаем имя пользователя
            cursor.execute("SELECT name FROM users WHERE id = %s", (user_id,))
            user_name = cursor.fetchone()["name"]

        # Отправляем сообщение через WebSocket в комнату события
        socketio.emit(
            f"chat_{event_id}",
            {"user_id": user_id, "name": user_name, "message": message},
            room=event_id
        )

        return jsonify({"message": "Message sent"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

# 🔹 Подключение к чату (WebSocket)
@socketio.on("join_chat")
def join_chat(data):
    event_id = data["event_id"]
    join_room(event_id)
    emit("chat_joined", {"message": f"User joined chat for event {event_id}"}, room=event_id)

# 🔹 Отключение от чата
@socketio.on("leave_chat")
def leave_chat(data):
    event_id = data["event_id"]
    leave_room(event_id)
    emit("chat_left", {"message": f"User left chat for event {event_id}"}, room=event_id)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
