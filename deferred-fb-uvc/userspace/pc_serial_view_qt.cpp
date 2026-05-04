#include <QtCore/QByteArray>
#include <QtCore/QCommandLineOption>
#include <QtCore/QCommandLineParser>
#include <QtCore/QDataStream>
#include <QtGui/QImage>
#include <QtGui/QPixmap>
#include <QtSerialPort/QSerialPort>
#include <QtSerialPort/QSerialPortInfo>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <QDebug>
#include <cstring>

namespace {
constexpr quint32 kMagic = 0x31424644U; // DFB1
constexpr int kHeaderSize = 11 * static_cast<int>(sizeof(quint32));
}

struct FrameHeader {
    quint32 magic = 0;
    quint32 seq = 0;
    quint32 width = 0;
    quint32 height = 0;
    quint32 bpp = 0;
    quint32 lineLength = 0;
    quint32 x1 = 0;
    quint32 y1 = 0;
    quint32 x2 = 0;
    quint32 y2 = 0;
    quint32 payloadSize = 0;
};

class SerialViewer : public QWidget {
public:
    SerialViewer(const QString &portName, int baudRate, QWidget *parent = nullptr)
        : QWidget(parent),
          preferredPort_(portName),
          baudRate_(baudRate),
          portCombo_(new QComboBox(this)),
          refreshButton_(new QPushButton("Refresh", this)),
          toggleButton_(new QPushButton("Connect", this)),
          imageLabel_(new QLabel(this)),
          statusLabel_(new QLabel(this))
    {
        auto *layout = new QVBoxLayout(this);
        auto *ctrlLayout = new QHBoxLayout();

        ctrlLayout->addWidget(new QLabel("Serial Port:", this));
        ctrlLayout->addWidget(portCombo_, 1);
        ctrlLayout->addWidget(refreshButton_);
        ctrlLayout->addWidget(toggleButton_);
        layout->addLayout(ctrlLayout);

        imageLabel_->setAlignment(Qt::AlignCenter);
        layout->addWidget(imageLabel_, 1);
        layout->addWidget(statusLabel_);
        setLayout(layout);
        resize(960, 600);

        serial_.setDataBits(QSerialPort::Data8);
        serial_.setParity(QSerialPort::NoParity);
        serial_.setStopBits(QSerialPort::OneStop);
        serial_.setFlowControl(QSerialPort::NoFlowControl);

        connect(&serial_, &QSerialPort::readyRead, this, [this]() { onReadyRead(); });
        connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshPorts(); });
        connect(toggleButton_, &QPushButton::clicked, this, [this]() {
            if (serial_.isOpen()) {
                closePort();
            } else {
                openSelectedPort();
            }
        });

        refreshPorts();
        openSelectedPort();
    }

private:
    void onReadyRead()
    {
        rxBuffer_.append(serial_.readAll());
        processBuffer();
    }

private:
    static bool parseHeader(const QByteArray &raw, FrameHeader &hdr)
    {
        if (raw.size() < kHeaderSize) {
            return false;
        }

        QByteArray tmp = raw;
        QDataStream ds(&tmp, QIODevice::ReadOnly);
        ds.setByteOrder(QDataStream::LittleEndian);
        ds >> hdr.magic >> hdr.seq >> hdr.width >> hdr.height >> hdr.bpp >> hdr.lineLength >> hdr.x1 >> hdr.y1 >> hdr.x2 >>
            hdr.y2 >> hdr.payloadSize;
        return ds.status() == QDataStream::Ok;
    }

    static int bytesPerPixel(quint32 bpp)
    {
        if (bpp == 16) return 2;
        if (bpp == 32) return 4;
        return 0;
    }

    void refreshPorts()
    {
        const QString current = portCombo_->currentData().toString();
        portCombo_->clear();

        const auto ports = QSerialPortInfo::availablePorts();
        for (const auto &portInfo : ports) {
            const QString label = QString("%1 (%2)").arg(portInfo.portName(), portInfo.description());
            portCombo_->addItem(label, portInfo.portName());
        }

        if (portCombo_->count() == 0) {
            statusLabel_->setText("No serial ports found.");
            toggleButton_->setEnabled(false);
            return;
        }

        toggleButton_->setEnabled(true);

        int idx = -1;
        if (!preferredPort_.isEmpty()) {
            idx = portCombo_->findData(preferredPort_);
        }
        if (idx < 0 && !current.isEmpty()) {
            idx = portCombo_->findData(current);
        }
        if (idx < 0) {
            idx = 0;
        }
        portCombo_->setCurrentIndex(idx);
    }

    void openSelectedPort()
    {
        if (portCombo_->count() == 0) {
            statusLabel_->setText("No serial port to open.");
            return;
        }

        const QString portName = portCombo_->currentData().toString();
        serial_.setPortName(portName);
        serial_.setBaudRate(baudRate_);

        if (!serial_.open(QIODevice::ReadOnly)) {
            statusLabel_->setText(QString("Failed to open %1: %2")
                                      .arg(portName, serial_.errorString()));
            return;
        }

        rxBuffer_.clear();
        toggleButton_->setText("Disconnect");
        statusLabel_->setText(QString("Listening on %1 @ %2").arg(portName).arg(baudRate_));
    }

    void closePort()
    {
        if (serial_.isOpen()) {
            serial_.close();
        }
        rxBuffer_.clear();
        toggleButton_->setText("Connect");
        statusLabel_->setText("Disconnected.");
    }

    void processBuffer()
    {
        while (true) {
            if (rxBuffer_.size() < kHeaderSize) {
                return;
            }

            FrameHeader hdr;
            if (!parseHeader(rxBuffer_.left(kHeaderSize), hdr)) {
                return;
            }

            if (hdr.magic != kMagic) {
                const QByteArray magicBytes(reinterpret_cast<const char *>(&kMagic), sizeof(kMagic));
                const int pos = rxBuffer_.indexOf(magicBytes, 1);
                if (pos < 0) {
                    rxBuffer_.clear();
                } else {
                    rxBuffer_.remove(0, pos);
                }
                continue;
            }

            const int bppBytes = bytesPerPixel(hdr.bpp);
            if (bppBytes == 0 || hdr.width == 0 || hdr.height == 0) {
                rxBuffer_.remove(0, kHeaderSize);
                continue;
            }

            if (hdr.lineLength < hdr.width * static_cast<quint32>(bppBytes) || hdr.y2 < hdr.y1 || hdr.x2 < hdr.x1 ||
                hdr.x2 >= hdr.width || hdr.y2 >= hdr.height || hdr.x1 != 0 || hdr.x2 != hdr.width - 1) {
                rxBuffer_.remove(0, kHeaderSize);
                continue;
            }

            const quint64 rectHeight = static_cast<quint64>(hdr.y2 - hdr.y1 + 1);
            const quint64 expectedPayload = rectHeight * static_cast<quint64>(hdr.lineLength);
            if (hdr.payloadSize != expectedPayload || hdr.payloadSize > 64U * 1024U * 1024U) {
                rxBuffer_.remove(0, kHeaderSize);
                continue;
            }

            const int totalSize = kHeaderSize + static_cast<int>(hdr.payloadSize);
            if (rxBuffer_.size() < totalSize) {
                return;
            }

            const QByteArray payload = rxBuffer_.mid(kHeaderSize, static_cast<int>(hdr.payloadSize));
            rxBuffer_.remove(0, totalSize);

            applyRect(hdr, payload);
            QImage img = decodeFullFrame();
            if (!img.isNull()) {
                imageLabel_->setPixmap(QPixmap::fromImage(img).scaled(imageLabel_->size(),
                                                                      Qt::KeepAspectRatio,
                                                                      Qt::SmoothTransformation));
                statusLabel_->setText(QString("seq=%1 %2x%3 bpp=%4 rect=(%5,%6)-(%7,%8)")
                                          .arg(hdr.seq)
                                          .arg(hdr.width)
                                          .arg(hdr.height)
                                          .arg(hdr.bpp)
                                          .arg(hdr.x1)
                                          .arg(hdr.y1)
                                          .arg(hdr.x2)
                                          .arg(hdr.y2));
            }
        }
    }

    void resetFramebuffer(const FrameHeader &hdr)
    {
        fbWidth_ = hdr.width;
        fbHeight_ = hdr.height;
        fbBpp_ = hdr.bpp;
        fbLineLength_ = hdr.lineLength;
        fbRaw_.fill(0, static_cast<int>(fbLineLength_ * fbHeight_));
    }

    void applyRect(const FrameHeader &hdr, const QByteArray &payload)
    {
        if (fbWidth_ != hdr.width || fbHeight_ != hdr.height || fbBpp_ != hdr.bpp || fbLineLength_ != hdr.lineLength ||
            fbRaw_.isEmpty()) {
            resetFramebuffer(hdr);
        }

        const int rectHeight = static_cast<int>(hdr.y2 - hdr.y1 + 1);
        const int lineBytes = static_cast<int>(hdr.lineLength);
        for (int row = 0; row < rectHeight; ++row) {
            const int dstOff = static_cast<int>((hdr.y1 + static_cast<quint32>(row)) * hdr.lineLength);
            const int srcOff = row * lineBytes;
            memcpy(fbRaw_.data() + dstOff, payload.constData() + srcOff, static_cast<size_t>(lineBytes));
        }
    }

    QImage decodeFullFrame() const
    {
        if (fbRaw_.isEmpty()) {
            return {};
        }

        QImage image(static_cast<int>(fbWidth_), static_cast<int>(fbHeight_), QImage::Format_RGB888);
        if (image.isNull()) {
            return {};
        }

        if (fbBpp_ == 16) {
            const auto *src = reinterpret_cast<const uchar *>(fbRaw_.constData());
            for (quint32 y = 0; y < fbHeight_; ++y) {
                uchar *dstLine = image.scanLine(static_cast<int>(y));
                const auto *srcLine = reinterpret_cast<const quint16 *>(src + y * fbLineLength_);
                for (quint32 x = 0; x < fbWidth_; ++x) {
                    const quint16 px = srcLine[x];
                    const uchar r = static_cast<uchar>(((px >> 11) & 0x1F) << 3);
                    const uchar g = static_cast<uchar>(((px >> 5) & 0x3F) << 2);
                    const uchar b = static_cast<uchar>((px & 0x1F) << 3);
                    dstLine[x * 3 + 0] = r;
                    dstLine[x * 3 + 1] = g;
                    dstLine[x * 3 + 2] = b;
                }
            }
            return image;
        }

        if (fbBpp_ == 32) {
            const auto *src = reinterpret_cast<const uchar *>(fbRaw_.constData());
            for (quint32 y = 0; y < fbHeight_; ++y) {
                uchar *dstLine = image.scanLine(static_cast<int>(y));
                const auto *srcLine = src + y * fbLineLength_;
                for (quint32 x = 0; x < fbWidth_; ++x) {
                    const int s = static_cast<int>(x * 4);
                    dstLine[x * 3 + 0] = srcLine[s + 2];
                    dstLine[x * 3 + 1] = srcLine[s + 1];
                    dstLine[x * 3 + 2] = srcLine[s + 0];
                }
            }
            return image;
        }

        return {};
    }

    QSerialPort serial_;
    QString preferredPort_;
    int baudRate_;
    QByteArray rxBuffer_;
    QByteArray fbRaw_;
    quint32 fbWidth_ = 0;
    quint32 fbHeight_ = 0;
    quint32 fbBpp_ = 0;
    quint32 fbLineLength_ = 0;
    QComboBox *portCombo_;
    QPushButton *refreshButton_;
    QPushButton *toggleButton_;
    QLabel *imageLabel_;
    QLabel *statusLabel_;
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setApplicationName("pc_serial_view_qt");
    QCoreApplication::setApplicationVersion("1.0");

    QCommandLineParser parser;
    parser.setApplicationDescription("Deferred FB serial viewer (Qt)");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption portOpt(QStringList() << "p"
                                             << "port",
                               "Serial port name (e.g. COM5 or /dev/ttyACM0).",
                               "port",
                               "COM5");
    QCommandLineOption baudOpt(QStringList() << "b"
                                             << "baud",
                               "Baud rate.",
                               "baud",
                               "2000000");
    parser.addOption(portOpt);
    parser.addOption(baudOpt);
    parser.process(app);

    bool ok = false;
    const int baud = parser.value(baudOpt).toInt(&ok);
    if (!ok || baud <= 0) {
        qCritical() << "Invalid baud rate:" << parser.value(baudOpt);
        return 1;
    }

    SerialViewer viewer(parser.value(portOpt), baud);
    viewer.setWindowTitle("DeferredFB Serial Viewer (Qt)");
    viewer.show();
    return app.exec();
}
