import json 

lines = open('./rooms.c', 'r').readlines()

rooms = {}

for line in lines:
    # Example line:
    # room_550(){  int result;   char v1;   pthread_mutex_lock(&stru_22A10);  v1 = getchar();  TEXT[PTR] = v1;  result = ++PTR;  if ( v1 == 117 )    result = pthread_mutex_unlock(&stru_22AD8);  if ( v1 == 111 )    return pthread_mutex_unlock(&stru_22628);  return result;}
    

    room_number = line.split('(')[0]
    locking_door = line.split('pthread_mutex_lock(&')[1].split(')')[0]
    
    doors = {}
    for unlocked_room in line.split('if ( v1 == ')[1:]:
        key = int(unlocked_room.split(' )')[0])
        door = unlocked_room.split('pthread_mutex_unlock(&')[1].split(')')[0]
        
        doors[door] = key
        print(f'\t{key} {chr(int(key))} - {door}')
    print(room_number, locking_door)

    room = { "locking_door_name": locking_door, "doors": doors }
    rooms[room_number] = room


with open('./rooms.json', 'w') as g:
    json.dump(rooms, g, indent=4)