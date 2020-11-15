/* tag: qt plugin framebuffer class description
 *
 * Copyright (C) 2003 Stefan Reinauer
 *
 * See the file "COPYING" for further information about
 * the copyright and warranty status of this work.
 */

#ifndef __framebufferwidget_h
#define __framebufferwidget_h

#include <qapplication.h>
#include <qwidget.h>
#include <qimage.h>
#include <qpainter.h>
#include <qmenubar.h>
#include <qpopupmenu.h>
#include <qmessagebox.h>
#include <qstatusbar.h>
#include <qtimer.h>

class FrameBufferWidget : public QWidget {
	Q_OBJECT
	public:
		FrameBufferWidget(QWidget *parent=0, const char *name=0);
		unsigned char *getFrameBuffer(void);

	public slots:
		void quit();
		void about();
		void aboutQt();
		void update();

	private:
		QImage     buffer;
		QMenuBar   *menu;
		QStatusBar *status;
		QTimer     *updatetimer;
		void paintEvent ( QPaintEvent * );
	protected:
		void keyPressEvent(QKeyEvent * e);
};

#endif
