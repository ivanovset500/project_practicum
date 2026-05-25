from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    full_name: Mapped[str] = mapped_column(String(250), default="")
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    tickets = relationship("Ticket", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Direction(Base):
    __tablename__ = "directions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    tickets = relationship("Ticket", back_populates="direction")


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(150))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="Заявка создана")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    direction_id: Mapped[Optional[int]] = mapped_column(ForeignKey("directions.id"), nullable=True)

    author = relationship("User", back_populates="tickets")
    direction = relationship("Direction", back_populates="tickets")
    comments = relationship("Comment", back_populates="ticket", cascade="all, delete-orphan", order_by="Comment.created_at")


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id"))
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    ticket = relationship("Ticket", back_populates="comments")
    author = relationship("User", back_populates="comments")
