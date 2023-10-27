tristan@O11:~/Code/CS472-Class-Files/hw2-echo-shell$ ./client -p "Echo test"
HEADER VALUES 
  Proto Type:    PROTO_CS_FUN
  Proto Ver:     VERSION_1
  Command:       CMD_PING_PONG
  Direction:     DIR_RECV
  Term:          TERM_FALL 
  Course:        NONE
  Pkt Len:       22

RECV FROM SERVER -> PONG: Echo test
tristan@O11:~/Code/CS472-Class-Files/hw2-echo-shell$ ./client -c CS577
HEADER VALUES 
  Proto Type:    PROTO_CS_FUN
  Proto Ver:     VERSION_1
  Command:       CMD_CLASS_INFO
  Direction:     DIR_RECV
  Term:          TERM_FALL 
  Course:        CS577
  Pkt Len:       12

RECV FROM SERVER -> CS577: Software architecture is important
tristan@O11:~/Code/CS472-Class-Files/hw2-echo-shell$ ./client
HEADER VALUES 
  Proto Type:    PROTO_CS_FUN
  Proto Ver:     VERSION_1
  Command:       CMD_CLASS_INFO
  Direction:     DIR_RECV
  Term:          TERM_FALL 
  Course:        CS472
  Pkt Len:       12

RECV FROM SERVER -> CS472: Welcome to computer networks
tristan@O11:~/Code/CS472-Class-Files/hw2-echo-shell$ ./client -c junk
HEADER VALUES 
  Proto Type:    PROTO_CS_FUN
  Proto Ver:     VERSION_1
  Command:       CMD_CLASS_INFO
  Direction:     DIR_RECV
  Term:          TERM_FALL 
  Course:        junk
  Pkt Len:       12

RECV FROM SERVER -> Requested Course Not Found







     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 COURSE REGISTRATION PROTOCOL                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | SEATS | SECTS |  REG  | OVER  |          Timeslots            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Pre-Requisites*                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  CLASS INFORMATION PROTOCOL                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | PROTO |  VER  |  CMD  |DIR|ATM|     AY: Academic Year         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             CC1: Course Code (First 4 Chars)                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       CC2: Course Code (Last 3 Chars)         |LEN: Msg Length|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     MSG: Message Data*                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    We could reuse some of the data from the class information protocol, while introducting fields for
    the new information required for course registration. Seats, sections, and fields for confirming registration
    and requesting section overrides could be handled in 4 bytes, timeslots are going to need more. Pre-requisite
    courses could take up an unknown amount of bytes, so this will have to be returned in a payload. The
    response from the server (whether the registration was successful or not) can be returned in the message
    data inside the class information protocol for consistency.
