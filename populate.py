
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import User, Base, Category, Item

engine = create_engine('sqlite:///categories.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
'''
A DBSession() instance establishes all conversations with the database
and represents a "staging zone" for all the objects loaded into the
database session object. Any change made against the objects in the
session won't be persisted into the database until you call
session.commit(). If you're not happy about the changes, you can
revert all of them back to the last commit by calling
session.rollback()
'''
session = DBSession()


# Create dummy user

User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# adding categories
soccer = Category(name="Soccer")

session.add(soccer)
session.commit()

basketball = Category(name="Basketball")

session.add(basketball)
session.commit()

baseball = Category(name="Baseball")

session.add(baseball)
session.commit()

frisbee = Category(name="Frisbee")

session.add(frisbee)
session.commit()

snowboard = Category(name="Snowboard")

session.add(snowboard)
session.commit()

rock = Category(name="Rock Climbing")

session.add(rock)
session.commit()

foosball = Category(name="Foosball")

session.add(foosball)
session.commit()

skate = Category(name="Skating")

session.add(skate)
session.commit()

hockey = Category(name="Hockey")

session.add(hockey)
session.commit()

# add a single item
snowboard2 = Item(
    name="Snowboard",
    description="Bob loves to snowboard and bought this at the store",
    category_id=5, user_id=1)

session.add(snowboard2)
session.commit()

print "added menu items!"
