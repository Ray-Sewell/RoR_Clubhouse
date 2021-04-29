class Post < ApplicationRecord
    belongs_to :user

    validates :body, presence: true, length: { minimum: 10, maximum: 150 }
end
