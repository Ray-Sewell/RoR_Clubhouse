class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  has_many :posts, dependent: :destroy

  validates :email, presence: true, length: { minimum: 4, maximum: 30 }
  validates :name, presence: true, length: { minimum: 3, maximum: 22 }
end
