#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
             tr("Open Sig file"), "C:/", tr("SIG Files (*.sig)"));
    //get offset from the line
    uint firstBytes = ui->firstBytesLineEdit->text().toUInt();
    PacketsParser packets(fileName, firstBytes);
    packets.packetParse();
    // fill lines with data
    ui->totalPackets->setText(QString::number(packets.getTotalPackets()));
    ui->ipv4TotalPackets->setText(QString::number(packets.getIPv4TotalPackets()));
    ui->ipv4TCPPackets->setText(QString::number(packets.getIPv4TCPPackets()));
    ui->ipv4UDPPackets->setText(QString::number(packets.getIPv4UDPPackets()));
    ui->ipv4ESPPackets->setText(QString::number(packets.getIPv4ESPPackets()));
    ui->ipv4GREPackets->setText(QString::number(packets.getIPv4GREPackets()));
    ui->ipv4ICMPPackets->setText(QString::number(packets.getIPv4ICMPPackets()));
    ui->ipv4EIGRPPackets->setText(QString::number(packets.getIPv4EIGRPPackets()));
    ui->ipv4OtherPackets->setText(QString::number(packets.getIPv4OtherPackets()));
    ui->ipv6TotalPackets->setText(QString::number(packets.getIPv6TotalPackets()));
    ui->ipv6TCPPackets->setText(QString::number(packets.getIPv6TCPPackets()));
    ui->ipv6UDPPackets->setText(QString::number(packets.getIPv6UDPPackets()));
    ui->ipv6ESPPackets->setText(QString::number(packets.getIPv6ESPPackets()));
    ui->ipv6GREPackets->setText(QString::number(packets.getIPv6GREPackets()));
    ui->ipv6ICMPPackets->setText(QString::number(packets.getIPv6ICMPPackets()));
    ui->ipv6EIGRPPackets->setText(QString::number(packets.getIPv6EIGRPPackets()));
    ui->ipv6OtherPackets->setText(QString::number(packets.getIPv6OtherPackets()));
    ui->OtherPackets->setText(QString::number(packets.getOtherTotalPackets()));

}
