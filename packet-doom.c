/* packet-doom.c
 * Routines for chocodoom dissection
 * Copyright 2020, doom <test@spamspam.xyz>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Chocolate Doom packet dissector.
 */

#include <config.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-doom.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-doom.h"
#endif


// Doom defines

#define NET_MAXPLAYERS 8
// Maximum length of a player's name.
#define MAXPLAYERNAME 30


/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_doom(void);
void proto_register_doom(void);

/* Initialize the protocol and registered fields */
static int proto_doom = -1;
static int hf_doom_packet_type = -1;
static int hf_doom_version = -1;
static int hf_doom_server_state = -1;
static int hf_doom_num_players = -1;
static int hf_doom_max_players = -1;
static int hf_doom_gamemode = -1;
static int hf_doom_gamemission = -1;
static int hf_doom_ready_players = -1;
static int hf_doom_num_drones = -1;
static int hf_doom_is_controller =-1;
static int hf_doom_is_console = -1;
static int hf_doom_description = -1;
static int hf_doom_protocol_version = -1;
static int hf_doom_player_name = -1;
static int hf_doom_player_ip = -1;
static int hf_doom_wad_sha1sum = -1;
static int hf_doom_deh_sha1sum = -1;
static int hf_doom_is_freedoom = -1;
static int hf_doom_magic_number = -1;
static int hf_doom_protocolid = -1;
static int hf_doom_lowres_turn = -1;
static int hf_doom_ack_seq = -1;
static int hf_doom_packet_sequence = -1;
static int hf_doom_tics_amount = -1;
static int hf_doom_gamedata_lowres = -1;
static int hf_doom_gamedata_latency = -1;
static int hf_doom_temp3 = -1;
static int hf_doom_gamedata_type = -1;
static int hf_doom_gamedata_flags = -1;
static int hf_doom_receivedtics = -1;


static int hf_doom_NET_TICDIFF_FORWARD = -1;
static int hf_doom_NET_TICDIFF_FORWARD_VALUE = -1;
static int hf_doom_NET_TICDIFF_SIDE = -1;
static int hf_doom_NET_TICDIFF_SIDE_VALUE = -1;
static int hf_doom_NET_TICDIFF_TURN = -1;
static int hf_doom_NET_TICDIFF_TURN_VALUE = -1;
static int hf_doom_NET_TICDIFF_TURN_VALUE_LOWRES = -1;
static int hf_doom_NET_TICDIFF_BUTTONS = -1;
static int hf_doom_NET_TICDIFF_BUTTONS_VALUE = -1;
static int hf_doom_NET_TICDIFF_CONSISTANCY = -1;
static int hf_doom_NET_TICDIFF_CONSISTANCY_VALUE = -1;
static int hf_doom_NET_TICDIFF_CHATCHAR = -1;
static int hf_doom_NET_TICDIFF_CHATCHAR_VALUE = -1;
static int hf_doom_NET_TICDIFF_RAVEN = -1;
static int hf_doom_NET_TICDIFF_RAVEN_VALUE = -1;
static int hf_doom_NET_TICDIFF_STRIFE = -1;
static int hf_doom_NET_TICDIFF_STRIFE_VALUE = -1;
static int hf_doom_NET_TICDIFF_ACTIVEPLAYER = -1;

static int hf_doom_NET_GAMESETTINGS_TICDUP = -1;
static int hf_doom_NET_GAMESETTINGS_EXTRATICS = -1;
static int hf_doom_NET_GAMESETTINGS_DEATHMATCH = -1;
static int hf_doom_NET_GAMESETTINGS_EPISODE = -1;
static int hf_doom_NET_GAMESETTINGS_NOMONSTERS = -1;
static int hf_doom_NET_GAMESETTINGS_FAST_MONSTERS = -1;
static int hf_doom_NET_GAMESETTINGS_RESPAWN_MONSTERS = -1;
static int hf_doom_NET_GAMESETTINGS_MAP = -1;
static int hf_doom_NET_GAMESETTINGS_SKILL = -1;
static int hf_doom_NET_GAMESETTINGS_GAMEVERSION = -1;
static int hf_doom_NET_GAMESETTINGS_LOWRES_TURN = -1;
static int hf_doom_NET_GAMESETTINGS_NEW_SYNC = -1;
static int hf_doom_NET_GAMESETTINGS_TIMELIMIT = -1;
static int hf_doom_NET_GAMESETTINGS_LOADGAME = -1;
static int hf_doom_NET_GAMESETTINGS_RANDOM = -1;
static int hf_doom_NET_GAMESETTINGS_NUM_PLAYERS = -1;
static int hf_doom_NET_GAMESETTINGS_CONSOLEPLAYER = -1;
static int hf_doom_NET_GAMESETTINGS_PLAYER_CLASSES = -1;




static expert_field ei_doom_expert = EI_INIT;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define doom_UDP_PORT 2342

static guint udp_port_pref = doom_UDP_PORT;


/* Flag bits Tick action*/

#define NET_TICDIFF_FORWARD      (1 << 0)
#define NET_TICDIFF_SIDE         (1 << 1)
#define NET_TICDIFF_TURN         (1 << 2)
#define NET_TICDIFF_BUTTONS      (1 << 3)
#define NET_TICDIFF_CONSISTANCY  (1 << 4)
#define NET_TICDIFF_CHATCHAR     (1 << 5)
#define NET_TICDIFF_RAVEN        (1 << 6)
#define NET_TICDIFF_STRIFE       (1 << 7)


//#define FUNC_SENDTICK 6

typedef enum
{
    // Protocol introduced with Chocolate Doom v3.0. Each compatibility-
    // breaking change to the network protocol will produce a new protocol
    // number in this enum.
    NET_PROTOCOL_CHOCOLATE_DOOM_0,
    // Add your own protocol here; be sure to add a name for it to the list
    // in net_common.c too.
    NET_NUM_PROTOCOLS,
    NET_PROTOCOL_UNKNOWN,
} net_protocol_t;

typedef enum
{
    NET_PACKET_TYPE_SYN,
    NET_PACKET_TYPE_ACK, // deprecated
    NET_PACKET_TYPE_REJECTED,
    NET_PACKET_TYPE_KEEPALIVE,
    NET_PACKET_TYPE_WAITING_DATA,
    NET_PACKET_TYPE_GAMESTART,
    NET_PACKET_TYPE_GAMEDATA,
    NET_PACKET_TYPE_GAMEDATA_ACK,
    NET_PACKET_TYPE_DISCONNECT,
    NET_PACKET_TYPE_DISCONNECT_ACK,
    NET_PACKET_TYPE_RELIABLE_ACK,
    NET_PACKET_TYPE_GAMEDATA_RESEND,
    NET_PACKET_TYPE_CONSOLE_MESSAGE,
    NET_PACKET_TYPE_QUERY,
    NET_PACKET_TYPE_QUERY_RESPONSE,
    NET_PACKET_TYPE_LAUNCH,
    NET_PACKET_TYPE_NAT_HOLE_PUNCH,
} net_packet_type_t;


typedef enum
{
    // waiting for the game to be "launched" (key player to press the start
    // button)
    SERVER_WAITING_LAUNCH,
    // game has been launched, we are waiting for all players to be ready
    // so the game can start.
    SERVER_WAITING_START,
    // in a game
    SERVER_IN_GAME,
} net_server_state_t;

typedef enum
{
    shareware,       // Doom/Heretic shareware
    registered,      // Doom/Heretic registered
    commercial,      // Doom II/Hexen
    retail,          // Ultimate Doom
    indetermined     // Unknown.
} GameMode_t;



static const value_string doom_gamemode[] = {
    {shareware, "Shareware"},
    {registered, "Registered"},
    {commercial, "Commercial"},
    {retail,"retail"},
    {indetermined, "indetermined"},
    {0,NULL}
};

static const value_string doom_gamemission[] = {
    {0, "doom.wad"},
    {1, "doom2.wad"},
    {0,NULL}
};

static const value_string doom_serverstate[] = {
    {SERVER_WAITING_LAUNCH, "Server started, waiting for launch"},
    {SERVER_WAITING_START,"Game launched, Waiting for start"},
    {SERVER_IN_GAME,"Server in Game"},
    {0,NULL}
};


static const value_string doom_func_vals[] = {
    {NET_PACKET_TYPE_SYN,"Syn"},
    {NET_PACKET_TYPE_ACK, "Ack"}, // deprecated
    {NET_PACKET_TYPE_REJECTED,"Rejected"},
    {NET_PACKET_TYPE_KEEPALIVE,"Keepalive"},
    {NET_PACKET_TYPE_WAITING_DATA,"Waiting data"},
    {NET_PACKET_TYPE_GAMESTART,"Game Start"},
    {NET_PACKET_TYPE_GAMEDATA,"Gamedata"},
    {NET_PACKET_TYPE_GAMEDATA_ACK,"Gamedata Ack"},
    {NET_PACKET_TYPE_DISCONNECT,"Disconnect"},
    {NET_PACKET_TYPE_DISCONNECT_ACK,"Disconnect Ack"},
    {NET_PACKET_TYPE_RELIABLE_ACK,"Reliable Ack"},
    {NET_PACKET_TYPE_GAMEDATA_RESEND,"Gamedata resend"},
    {NET_PACKET_TYPE_CONSOLE_MESSAGE,"Console message"},
    {NET_PACKET_TYPE_QUERY,"Query"},
    {NET_PACKET_TYPE_QUERY_RESPONSE,"Query response"},
    {NET_PACKET_TYPE_LAUNCH,"Launch"},
    {NET_PACKET_TYPE_NAT_HOLE_PUNCH,"NAT Hole Punch"},
    {0,NULL}
};



typedef struct
{
    signed char	forwardmove;	// *2048 for move
    signed char	sidemove;	// *2048 for move
    short angleturn;            // <<16 for angle delta
    guint8 chatchar;
    guint8 buttons;
    // villsa [STRIFE] according to the asm,
    // consistancy is a short, not a byte
    guint8 consistancy;           // checks for net game

    // villsa - Strife specific:

    guint8 buttons2;
    int inventory;
   
    // Heretic/Hexen specific:

    guint8 lookfly;               // look/fly up/down/centering
    guint8 arti;                  // artitype_t to use
} ticcmd_t;

typedef struct
{
    unsigned int diff;
    ticcmd_t cmd;
} net_ticdiff_t;

// Complete set of ticcmds from all players

typedef struct 
{
    signed int latency;
    unsigned int seq;
    gboolean playeringame[4];
    net_ticdiff_t cmds[4];
} net_full_ticcmd_t;



/* Initialize the subtree pointers */
static gint ett_doom = -1;
static gint ett_doom_user_tree = -1;
static gint ett_doom_gamedata_flags = -1;


static const int * doom_gamedate_flags[] = {
    &hf_doom_NET_TICDIFF_FORWARD,
    &hf_doom_NET_TICDIFF_SIDE,
    &hf_doom_NET_TICDIFF_TURN,
    &hf_doom_NET_TICDIFF_BUTTONS,
    &hf_doom_NET_TICDIFF_CONSISTANCY,
    &hf_doom_NET_TICDIFF_CHATCHAR,
    &hf_doom_NET_TICDIFF_RAVEN,
    &hf_doom_NET_TICDIFF_STRIFE,
    NULL
};
  


#define doom_MIN_LENGTH 2

/* Code to actually dissect the packets */
static int dissect_doom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *expert_ti;
    proto_tree *doom_tree;


    //proto_tree *doom_players_tree;
    /* Other misc. local variables. */
    guint       offset = 0;
    int         len    = 0;

    guint8 func_code;
    guint8 flags;

    func_code = tvb_get_guint8(tvb,offset+1);

    /*** HEURISTICS ***/

    if (tvb_reported_length(tvb) < doom_MIN_LENGTH)
        return 0;

    if (tvb_captured_length(tvb) < 1)
        return 0;

    if ( 0 )
        return 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'doom',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of doom */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "doom");

#if 1
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(func_code,doom_func_vals, "Unknown function (%d)"));


    /*** PROTOCOL TREE ***/

    ti = proto_tree_add_item(tree, proto_doom, tvb, 0, -1, ENC_NA);
    doom_tree = proto_item_add_subtree(ti, ett_doom);

    proto_tree_add_uint(doom_tree, hf_doom_packet_type, tvb, offset, len, func_code);

    int len2 = tvb_strnlen(tvb,2,225);
    int numplayers = -1;
    int tics_amount = -1;
    int tic_lowresturn = -1;

    offset +=2;

     switch(func_code){
        case NET_PACKET_TYPE_GAMESTART:
            //from server to client
            proto_tree_add_item(doom_tree, hf_doom_ack_seq, tvb,offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_TICDUP, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_EXTRATICS, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_DEATHMATCH, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_NOMONSTERS, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_FAST_MONSTERS, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_RESPAWN_MONSTERS, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_EPISODE, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_MAP, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_SKILL, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_GAMEVERSION, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_LOWRES_TURN, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_NEW_SYNC, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_TIMELIMIT, tvb, offset,4, ENC_NA);
            offset += 4;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_LOADGAME, tvb, offset,1, ENC_NA);
            offset += 1;
            // RANDOM = Strife Only
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_RANDOM, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_NUM_PLAYERS, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_CONSOLEPLAYER, tvb, offset,1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_NET_GAMESETTINGS_PLAYER_CLASSES, tvb, offset,1, ENC_NA);
        break;

        case NET_PACKET_TYPE_LAUNCH:
            proto_tree_add_item(doom_tree, hf_doom_ack_seq, tvb,offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_num_players, tvb,offset, 1, ENC_NA);
        break;

        case NET_PACKET_TYPE_SYN:
            // Server sends SYN
            if(tvb_get_guint8(tvb,0) == 0x80){
                offset += 1;
                len2 = tvb_strnlen(tvb,offset,225)+1;
                proto_tree_add_item(doom_tree, hf_doom_description, tvb,offset, len2, ENC_NA);
                offset += len2;
                len2 = tvb_strnlen(tvb,offset,225)+1;
                proto_tree_add_item(doom_tree, hf_doom_protocol_version, tvb,offset, len2, ENC_NA);

                
            // Client sends SYN
            }else{
                proto_tree_add_item(doom_tree,hf_doom_magic_number,tvb,offset,4,ENC_NA);
                offset += 4 ;
                len2 = tvb_strnlen(tvb,offset,225)+1;
                proto_tree_add_item(doom_tree, hf_doom_description, tvb,offset, len2, ENC_NA);
                offset += len2;
                proto_tree_add_item(doom_tree, hf_doom_protocolid, tvb, offset,1, ENC_NA);
                offset += 1;
                len2 = tvb_strnlen(tvb,offset,225)+1;
                proto_tree_add_item(doom_tree, hf_doom_protocol_version, tvb,offset, len2, ENC_NA);
                offset += len2;
                proto_tree_add_item(doom_tree, hf_doom_gamemode, tvb,offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(doom_tree, hf_doom_gamemission, tvb,offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(doom_tree, hf_doom_lowres_turn, tvb,offset, 1, ENC_NA);
                offset +=1;
                proto_tree_add_item(doom_tree,hf_doom_num_drones,tvb,offset,1,ENC_NA);
                offset += 1;
                proto_tree_add_item(doom_tree, hf_doom_max_players, tvb,offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(doom_tree,hf_doom_is_freedoom,tvb,offset,1,ENC_NA);
                offset += 1;
                proto_tree_add_item(doom_tree,hf_doom_wad_sha1sum,tvb,offset,20,ENC_NA);
                offset += 20;
                proto_tree_add_item(doom_tree,hf_doom_deh_sha1sum,tvb,offset,20,ENC_NA);
                offset += 20;
                offset += 1;
                len2 = tvb_strnlen(tvb,offset,225)+1;
                proto_tree_add_item(doom_tree,hf_doom_player_name,tvb,offset,len2,ENC_NA);
            }
            break;
        case NET_PACKET_TYPE_RELIABLE_ACK:
            proto_tree_add_item(doom_tree, hf_doom_ack_seq, tvb,offset, 1, ENC_NA);
            break;

        case NET_PACKET_TYPE_QUERY_RESPONSE:
            proto_tree_add_item(doom_tree, hf_doom_version, tvb,offset, len2, ENC_ASCII);
            offset += len2+1;
            proto_tree_add_item(doom_tree, hf_doom_server_state, tvb,offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_num_players, tvb,offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_max_players, tvb,offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_gamemode, tvb,offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree, hf_doom_gamemission, tvb,offset, 1, ENC_NA);
            offset +=1;
            len2 = tvb_strnlen(tvb,offset,225);
            proto_tree_add_item(doom_tree, hf_doom_description, tvb,offset, len2, ENC_NA);
            offset += len2+2;
            len2 = tvb_strnlen(tvb,offset,225);
            proto_tree_add_item(doom_tree, hf_doom_protocol_version, tvb,offset, len2, ENC_NA);

            break;
        
        case NET_PACKET_TYPE_GAMEDATA:
            
            proto_tree_add_item(doom_tree,hf_doom_receivedtics,tvb,offset,1,ENC_NA);
            offset += 1;
            
            // if packet is coming from client read additional value. Ugly hack
            if(pinfo->srcport > pinfo->destport){
                
                proto_tree_add_item(doom_tree,hf_doom_packet_sequence,tvb,offset,1,ENC_NA);
                offset += 1;
            }
            tics_amount = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(doom_tree,hf_doom_tics_amount,tvb,offset,1,ENC_NA);
            offset += 1;

            while (tics_amount){
                tic_lowresturn = tvb_get_guint8(tvb,offset);
                proto_tree_add_item(doom_tree,hf_doom_gamedata_lowres,tvb,offset,1,ENC_NA);
                offset += 1;
                proto_tree_add_item(doom_tree,hf_doom_gamedata_latency,tvb,offset,1,ENC_NA);
                offset += 1;
                // if packet is coming from server read additional value. Ugly hack
                if(pinfo->srcport < pinfo->destport){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_ACTIVEPLAYER,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_bitmask_value_with_flags(doom_tree, tvb, offset, hf_doom_gamedata_flags, ett_doom_gamedata_flags, doom_gamedate_flags, flags, BMT_NO_FALSE|BMT_NO_TFS);
                offset += 1;
                if (flags & NET_TICDIFF_FORWARD){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_FORWARD_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                if (flags & NET_TICDIFF_SIDE){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_SIDE_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                if (flags & NET_TICDIFF_TURN){
                    if (tic_lowresturn){
                        proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_TURN_VALUE_LOWRES,tvb,offset,1,ENC_NA);
                        offset += 1;
                    }
                    else
                    {
                        proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_TURN_VALUE,tvb,offset,2,ENC_NA);
                        offset += 2;
                    }
                }
                if (flags & NET_TICDIFF_BUTTONS){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_BUTTONS_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                if (flags & NET_TICDIFF_CONSISTANCY){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_CONSISTANCY_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                if (flags & NET_TICDIFF_CHATCHAR){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_CHATCHAR_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                if (flags & NET_TICDIFF_RAVEN){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_RAVEN_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                if (flags & NET_TICDIFF_STRIFE){
                    proto_tree_add_item(doom_tree,hf_doom_NET_TICDIFF_STRIFE_VALUE,tvb,offset,1,ENC_NA);
                    offset += 1;
                }
                tics_amount -= 1;
            }
            
            break;


        case NET_PACKET_TYPE_WAITING_DATA:
            proto_tree_add_item(doom_tree,hf_doom_num_players,tvb,offset,1,ENC_NA);
            numplayers = tvb_get_gint8(tvb,offset);
            offset +=1;
            proto_tree_add_item(doom_tree,hf_doom_num_drones,tvb,offset,1,ENC_NA);
            offset +=1;
            proto_tree_add_item(doom_tree,hf_doom_ready_players,tvb,offset,1,ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree,hf_doom_max_players,tvb,offset,1,ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree,hf_doom_is_controller,tvb,offset,1,ENC_NA);
            offset += 1;
            proto_tree_add_item(doom_tree,hf_doom_is_console, tvb, offset,1,ENC_NA);
            offset += 1;
            proto_tree *doom_user_tree = NULL;
            doom_user_tree = proto_tree_add_subtree(doom_tree, tvb, offset, -1, ett_doom_user_tree, NULL, "Players");
            while(numplayers){
                len2 = tvb_strnlen(tvb,offset,225);
                proto_tree_add_item(doom_user_tree, hf_doom_player_name, tvb, offset, len2, ENC_NA);
                offset += len2+1;
                len2 = tvb_strnlen(tvb,offset,225);
                proto_tree_add_item(doom_user_tree, hf_doom_player_ip, tvb, offset, len2, ENC_NA);
                offset += len2+1;
                numplayers -= 1;
            }
            proto_tree_add_item(doom_tree,hf_doom_wad_sha1sum,tvb,offset,20,ENC_NA);
            offset += 20;
            proto_tree_add_item(doom_tree,hf_doom_deh_sha1sum,tvb,offset,20,ENC_NA);
            offset += 20;
            proto_tree_add_item(doom_tree,hf_doom_is_freedoom,tvb,offset,1,ENC_NA);
            break;
        


    }

    if ( 0 )
        /* value of hf_doom_sample_field isn't what's expected */
        expert_add_info(pinfo, expert_ti, &ei_doom_expert);

    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_doom(void)
{
    module_t        *doom_module;
    expert_module_t *expert_doom;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_doom_packet_type,{ "Packet Type", "doom.packet_type",FT_UINT8, BASE_DEC, VALS(doom_func_vals), 0x0,"Doom Message Type", HFILL }},
        { &hf_doom_version,{"Doom Version","doom.version",FT_STRING,BASE_NONE,NULL,0x0,"NULL", HFILL}},
        { &hf_doom_description,{"Server Description","doom.description",FT_STRING,BASE_NONE,NULL,0x0,"NULL", HFILL}},
        { &hf_doom_server_state,{"Server State","doom.server_state",FT_UINT8,BASE_DEC,VALS(doom_serverstate),0x0,"Server State",HFILL}},
        { &hf_doom_num_players,{"Players active","doom.activeplayers",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_ready_players,{"Players ready","doom.readyplayers",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_num_drones,{"Active Drones","doom.activedrones",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_is_controller,{"Is Controller","doom.iscontroller",FT_BOOLEAN,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_is_console,{"Is Consoleplayer","doom.isconsole",FT_BOOLEAN,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_max_players,{"Maximum Players","doom.maxplayers",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_gamemode,{"Gamemode","doom.gamemode",FT_UINT8,BASE_DEC,VALS(doom_gamemode),0x0,"Gamemode",HFILL}},
        { &hf_doom_gamemission,{"Gamemission","doom.gamemission",FT_UINT8,BASE_DEC,VALS(doom_gamemission),0x0,"iwad",HFILL}},
        { &hf_doom_protocol_version,{"Protocol Version","doom.protocol_version",FT_STRING,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_player_name,{"Player Name","doom.protocol_version",FT_STRING,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_player_ip,{"Player IP address","doom.protocol_version",FT_STRING,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_wad_sha1sum,{"SHA1 checksum wad file","doom.wad_sha1sum",FT_BYTES,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_deh_sha1sum,{"SHA1 checksum deh file","doom.deh_sha1sum",FT_BYTES,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_is_freedoom,{"Is freedoom","doom.isfreedoom",FT_BOOLEAN,BASE_NONE,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_magic_number,{"Magic Number","doom.magic_number",FT_UINT32,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_protocolid,{"Protocol ID","doom.protocol_id",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_lowres_turn,{"Lowres turn","doom.lowres_turn",FT_BOOLEAN,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_ack_seq,{"Reliable Ack Number","doom.ack_seq",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_packet_sequence,{"Packet Sequence","doom.packet_seq",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_tics_amount,{"Number of Tics","doom.tics_mount",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_gamedata_lowres,{"Lowres Turn","doom.temp1",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_gamedata_latency,{"Latency","doom.latency",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_temp3,{"Unknown Value","doom.temp3",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_gamedata_type,{"Command Type","doom.temp4",FT_UINT8,BASE_HEX,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_gamedata_flags,{"Gamedata Type","doom.flags",FT_UINT8,BASE_HEX,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_FORWARD,{ "Forward Move",  "doom.flags.forwardmove",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_FORWARD,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_FORWARD_VALUE,{ "Forward Action",  "doom.gamedata.forward",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_SIDE,{ "Side Move",  "doom.flags.sidemove",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_SIDE,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_SIDE_VALUE,{ "Side Direction",  "doom.gamedata.sidemove",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_TURN,{ "Turn Move",  "doom.flags.turnmove",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_TURN,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_TURN_VALUE,{ "Turn Value",  "doom.flags.turnmove",FT_UINT16,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_TURN_VALUE_LOWRES,{ "Turn Value",  "doom.flags.turnmove_lowres",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_BUTTONS,{ "Button press",  "doom.flags.button",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_BUTTONS,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_BUTTONS_VALUE,{ "Button press",  "doom.gamedata.button",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_CONSISTANCY,{ "Consistancy",  "doom.flags.constistancy",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_CONSISTANCY,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_CONSISTANCY_VALUE,{ "Consistancy",  "doom.gamedata.constistancy",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_CHATCHAR,{ "Chat Char",  "doom.flags.chatchar",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_CHATCHAR,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_CHATCHAR_VALUE,{"Character","doom.gamedata.char",FT_CHAR,BASE_HEX,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_RAVEN,{ "Raven",  "doom.flags.raven",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_RAVEN,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_RAVEN_VALUE,{ "Raven",  "doom.gamedata.raven",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_STRIFE,{ "Strife",  "doom.flags.strife",FT_BOOLEAN, 8, TFS(&tfs_yes_no), NET_TICDIFF_STRIFE,NULL, HFILL}},
        { &hf_doom_NET_TICDIFF_STRIFE_VALUE,{ "Strife",  "doom.gamedata.strife",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_TICDIFF_ACTIVEPLAYER,{ "Player Activity",  "doom.gamedate.playeractivity",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_TICDUP,{ "Ticudp",  "doom.gamesettings.ticdup",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_EXTRATICS,{ "Extratics",  "doom.gamesettings.extratics",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_DEATHMATCH,{ "Deathmatch",  "doom.gamesettings.deathmatch",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_EPISODE,{ "Episode",  "doom.gamesettings.episode",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_NOMONSTERS,{ "No Monsters",  "doom.gamesettings.nomonsters",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_FAST_MONSTERS,{ "Fast Monsters",  "doom.gamesettings.fast_monters",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_RESPAWN_MONSTERS,{ "Respawn Monsters",  "doom.gamesettings.respawn_monsters",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_MAP,{ "Map",  "doom.gamesettings.map",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_SKILL,{ "Skill",  "doom.gamesettings.skill",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_GAMEVERSION,{ "Gameversion",  "doom.gamesettings.gameversion",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_LOWRES_TURN,{ "Lowres turn",  "doom.gamesettings.lowres_turn",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_NEW_SYNC,{ "New Sync",  "doom.gamesettings.new_sync",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_TIMELIMIT,{ "Timelimit",  "doom.gamesettings.timelimit",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_LOADGAME,{ "Load game",  "doom.gamesettings.loadgame",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_RANDOM,{ "Random",  "doom.gamesettings.random",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_NUM_PLAYERS,{ "Num Players",  "doom.gamesettings.num_players",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_CONSOLEPLAYER,{ "Console Player",  "doom.gamesettings.consoleplayer",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_NET_GAMESETTINGS_PLAYER_CLASSES,{ "Player Classes",  "doom.gamesettings.player_classes",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}},
        { &hf_doom_receivedtics,{ "Last Received Tick",  "doom.gamedate.receivedtick",FT_UINT8,BASE_DEC,NULL,0x0,"NULL",HFILL}}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_doom,
        &ett_doom_user_tree,
        &ett_doom_gamedata_flags
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_doom_expert,
          { "doom.expert", PI_PROTOCOL, PI_ERROR,
            "EXPERTDESCR", EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_doom = proto_register_protocol("Chocolate Doom",
            "doom", "doom");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_doom, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_doom = expert_register_protocol(proto_doom);
    expert_register_field_array(expert_doom, ei, array_length(ei));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_doom in the following.
     */
    doom_module = prefs_register_protocol(proto_doom,proto_reg_handoff_doom);

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><doom>
     * preferences node.
     */
    doom_module = prefs_register_protocol_subtree("",proto_doom, proto_reg_handoff_doom);

    /* Register a simple example preference */
    prefs_register_bool_preference(doom_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &pref_hex);

    /* Register an example port preference */
    prefs_register_uint_preference(doom_module, "udp.port", "doom udp Port",
            " doom udp port if other than the default",
            10, &udp_port_pref);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_doom(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t doom_handle;
    static int current_port;

    if (!initialized) {
        /* Use create_dissector_handle() to indicate that
         * dissect_doom() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to chocodoom).
         */
        doom_handle = create_dissector_handle(dissect_doom,proto_doom);
        initialized = TRUE;

    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the doom_handle and the value the preference had at the time
         * you registered.  The doom_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        dissector_delete_uint("udp.port", current_port, doom_handle);
    }

    current_port = udp_port_pref;

    dissector_add_uint("udp.port", current_port, doom_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
