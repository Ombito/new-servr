# seed.py

from app import app, db
from models import User, Order, Payment
import secrets

def seed():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()

        # Create sample users
        user1 = User(
            full_name="John Doe",
            username="johndoe",
            email="john@example.com"
        )
        user1.password_hash = "password123"

        user2 = User(
            full_name="Jane Smith",
            username="janesmith",
            email="jane@example.com"
        )
        user2.password_hash = "securepassword"

        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Create sample orders
        order1 = Order(
            tracking_id="TRACK1001",
            total_amount=150.75,
            status="Pending",
            user_id=user1.id
        )

        order2 = Order(
            tracking_id="TRACK1002",
            total_amount=299.99,
            status="Pending",
            user_id=user2.id
        )

        db.session.add(order1)
        db.session.add(order2)
        db.session.commit()

        # Create sample payments
        payment1 = Payment(
            order_id=order1.id,
            payment_method="Credit Card",
            payment_details="Card Number: **** **** **** 1234",
            status="Completed"
        )

        payment2 = Payment(
            order_id=order2.id,
            payment_method="PayPal",
            payment_details="PayPal Account: jane@paypal.com",
            status="Completed"
        )

        db.session.add(payment1)
        db.session.add(payment2)
        db.session.commit()

    print("Database seeded successfully!")

if __name__ == '__main__':
    seed()
