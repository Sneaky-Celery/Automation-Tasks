# Author: Sneaky Celery

def estimate(cost):     #This function accepts a dictionary as 'cost'
    base_fee = 40.00       
    for key,val in cost.items():    #This loop goes through each key and value in the parameter
        #If the key passed through the parameter is anything in the following lists
        #Multiply the user's input by the cost associated with that room-type, replace the value in [key]
        if key in ['mud rooms', 'stairs and halls', 'bedrooms']:
            cost[key] = val * 10.00    
        elif key in ['living rooms', 'dining rooms']:   
            cost[key] = val * 15.00
        elif key in ['bathrooms', 'kitchens']:
            cost[key] = val * 20.00   
    
    total = (base_fee + sum(cost.values())) * 1.089   #Simple math adding all values in a sum and adding tax
    return total    #Returns the total to the user

rooms = dict()      #Create an empty dictionary to allow for additional room-types to be added easily
print('')           #in the future.
#Create a Title for the program that tells the user what the intention of this program is
print('-' * 42)
print('Cleaning Service Estimate Calculator'.center(42))
print('-' * 42)
#Instruct the user on what is expected of them.
print('''   
Input the number of rooms for each of the following.
     ''')

while True:     #True loop to handle all invalid input exceptions
    try:        #Each individual prompt requires valid input before moving on
        rooms['bedrooms'] = float(input('Bedrooms: '))          #Create a ['key'] and add it the empty
        rooms['bathrooms'] = float(input('Bathrooms: '))        #dictionary.  Prompt the user to input
        rooms['kitchens'] = float(input('Kitchens: '))          #a number and convert it to a float type
        rooms['dining rooms'] = float(input('Dining rooms: '))  #to allow for 1.5 and 2.5 type bathrooms
        rooms['mud rooms'] = float(input('Mud rooms or laundry rooms: '))
        rooms['stairs and halls'] = float(input('Staircases and hallways: '))
        rooms['living rooms'] = float(input('Living rooms, Great rooms, or Family rooms: '))
        break
    except ValueError:('Invalid input.  Please input a valid number.')  #Message to re-prompt the user.

print('Your Estimate: ${:.2f}'.format(estimate(rooms)))     #Print the estimate in a readable format.
