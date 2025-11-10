import json

with open('./rooms.json', 'r') as g:
    rooms = json.load(g)

path = chr(114) # Key to exit_door
start_room = 'room_624' # Room that leads to the exit_door

current_room = start_room

while('monkey'):
    locking_door = rooms[current_room]['locking_door_name']
    found = False
    for room in rooms.keys():
        for door in rooms[room]["doors"].keys():
            if door == locking_door:
                current_room = room
                path += chr(rooms[room]["doors"][door]) 
                print(path)
                found = True

    if found: continue
    
    print(f'No door seems to unlock the current room: {current_room}')
    break

print()
print(f'Final path found: {path[::-1]}')