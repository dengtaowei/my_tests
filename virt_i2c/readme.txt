
// create i2c_client for i2c_slave
echo slave-virtual 0x1e > /sys/bus/i2c/devices/i2c-3/new_device
// set data to slave
i2cset -f -y 3 0x50 0 0x55
// get data from slave
i2cget -f -y 3 0x50 0