/* Basic ps2 port (keyboard/mouse) command handling.

   This file is copied (mostly) intact from SeaBIOS.
   It is covered by the GNU Lesser General Public License, v3.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; see the file COPYING.  If not see
   <http://www.gnu.org/licenses/>.  */

#ifndef PS2PORT_H
#define PS2PORT_H

typedef uint8_t u8;

// Standard commands.
#define I8042_CMD_CTL_RCTR      0x0120
#define I8042_CMD_CTL_WCTR      0x1060
#define I8042_CMD_CTL_TEST      0x01aa

#define I8042_CMD_KBD_TEST      0x01ab
#define I8042_CMD_KBD_DISABLE   0x00ad
#define I8042_CMD_KBD_ENABLE    0x00ae

#define I8042_CMD_AUX_DISABLE   0x00a7
#define I8042_CMD_AUX_ENABLE    0x00a8
#define I8042_CMD_AUX_SEND      0x10d4

// Keyboard commands
#define ATKBD_CMD_SETLEDS       0x10ed
#define ATKBD_CMD_SSCANSET      0x10f0
#define ATKBD_CMD_GETID         0x02f2
#define ATKBD_CMD_ENABLE        0x00f4
#define ATKBD_CMD_RESET_DIS     0x00f5
#define ATKBD_CMD_RESET_BAT     0x02ff

// Mouse commands
#define PSMOUSE_CMD_SETSCALE11  0x00e6
#define PSMOUSE_CMD_SETSCALE21  0x00e7
#define PSMOUSE_CMD_SETRES      0x10e8
#define PSMOUSE_CMD_GETINFO     0x03e9
#define PSMOUSE_CMD_GETID       0x02f2
#define PSMOUSE_CMD_SETRATE     0x10f3
#define PSMOUSE_CMD_ENABLE      0x00f4
#define PSMOUSE_CMD_DISABLE     0x00f5
#define PSMOUSE_CMD_RESET_BAT   0x02ff

// Status register bits.
#define I8042_STR_PARITY        0x80
#define I8042_STR_TIMEOUT       0x40
#define I8042_STR_AUXDATA       0x20
#define I8042_STR_KEYLOCK       0x10
#define I8042_STR_CMDDAT        0x08
#define I8042_STR_MUXERR        0x04
#define I8042_STR_IBF           0x02
#define I8042_STR_OBF           0x01

// Control register bits.
#define I8042_CTR_KBDINT        0x01
#define I8042_CTR_AUXINT        0x02
#define I8042_CTR_IGNKEYLOCK    0x08
#define I8042_CTR_KBDDIS        0x10
#define I8042_CTR_AUXDIS        0x20
#define I8042_CTR_XLATE         0x40

// functions
void i8042_reboot(void);
int ps2_kbd_command(int command, u8 *param);
int ps2_mouse_command(int command, u8 *param);
void ps2port_setup(void);

#endif // ps2port.h
