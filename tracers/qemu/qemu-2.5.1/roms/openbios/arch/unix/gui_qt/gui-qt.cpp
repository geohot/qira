/* tag: qt user interface fb class
 *
 * Copyright (C) 2003-2004 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#include "gui-qt.h"
#include "logo.xpm"

#include <iostream>

static const int sizex=640;
static const int sizey=480;
static const int depth=8;

static unsigned char color[256][3]={
	{ 0x00, 0x00, 0x00 },
	{ 0x00, 0x00, 0xaa },
	{ 0x00, 0xaa, 0x00 },
	{ 0x00, 0xaa, 0xaa },
	{ 0xaa, 0x00, 0x00 },
	{ 0xaa, 0x00, 0xaa },
	{ 0xaa, 0x55, 0x00 },
	{ 0xaa, 0xaa, 0xaa },
	{ 0x55, 0x55, 0x55 },
	{ 0x55, 0x55, 0xff },
	{ 0x55, 0xff, 0x55 },
	{ 0x55, 0xff, 0xff },
	{ 0xff, 0x55, 0x55 },
	{ 0xff, 0x55, 0xff },
	{ 0xff, 0xff, 0x55 },
	{ 0xff, 0xff, 0xff },
};

FrameBufferWidget::FrameBufferWidget(QWidget *parent, const char * name)
: QWidget(parent, name, Qt::WType_TopLevel)
{
	setCaption ("OpenBIOS");
	setIcon(QPixmap(logo));

	QPopupMenu *file = new QPopupMenu (this);

	file->insertItem( "E&xit",  this, SLOT(quit()), CTRL+Key_Q );

	QPopupMenu *help = new QPopupMenu( this );
	help->insertItem("&About OpenBIOS", this, SLOT(about()), CTRL+Key_H );
	help->insertItem( "About &Qt", this, SLOT(aboutQt()) );

	menu = new QMenuBar( this );
	Q_CHECK_PTR( menu );
	menu->insertItem( "&File", file );
	menu->insertSeparator();
	menu->insertItem( "&Help", help );
	menu->setSeparator( QMenuBar::InWindowsStyle );

	setFixedSize(sizex,sizey+menu->heightForWidth(sizex));

	buffer.create(sizex, sizey, depth, 256);

	for (int i=16; i < 256; i++) {
		color[i][0]=i;
		color[i][1]=i;
		color[i][2]=i;
	}

	for (int i=0; i< 256; i++)
		buffer.setColor(i, qRgb(color[i][0], color[i][1], color[i][2]));

	buffer.fill( 0 );

	updatetimer=new QTimer(this);
	connect( updatetimer, SIGNAL(timeout()), this, SLOT(update()) );
	updatetimer->start(200,FALSE);

	setMouseTracking( TRUE );
}

unsigned char * FrameBufferWidget::getFrameBuffer(void)
{
	return buffer.bits();
}

void FrameBufferWidget::paintEvent ( QPaintEvent * )
{
	QPainter p( this );
	p.drawImage(0,menu->heightForWidth(sizex),buffer, 0,0, sizex, sizey);
}

void FrameBufferWidget::about()
{
	QMessageBox::about( this, "About OpenBIOS",
			  "              Welcome to OpenBIOS 1.01\n"
			  "  IEEE 1275-1994 Open Firmware implementation\n\n"
			  "written by Stefan Reinauer <stepan@openbios.org>\n\n"
			  "                http://www.openbios.org/\n");
}

void FrameBufferWidget::aboutQt()
{
	QMessageBox::aboutQt( this, "OpenBIOS" );
}

void FrameBufferWidget::quit()
{
	extern volatile int gui_running;
	extern volatile int runforth;

	gui_running=0;
	interruptforth=1;

	qApp->quit();
}

void FrameBufferWidget::update()
{
	QPainter p( this );
	p.drawImage(0,menu->heightForWidth(sizex),buffer, 0,0, sizex, sizey);
}

void FrameBufferWidget::keyPressEvent(QKeyEvent * e)
{
	int a=e->ascii();
	if (a) {
		std::cout << " key '" << e->text() << "' pressed" << std::endl;
	}
}
