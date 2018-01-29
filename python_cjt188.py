#---------------------------------------------------------------------------------------------
# python_cjt188 v01 -- a tool to test CJ/T 188 meter through RS485 to M-Bus adapter
# BSD license is applied to this code
#
# Python 2.7 is supported
# Copyright by Aixi Wang (aixi.wang@hotmail.com)
# Tested with DN15 flow meter as slave device. USB type M-Bus adapter as master node.
#
# support functions:
#-------------------------------------
# read addr                    yes
# set addr                     yes
# read meter data              yes
# reset base initial value     no
#-------------------------------------
# Found issues:
# 1. crc error -- fixed by changing usb M-Bus adapter (www.msi-automation.com)
# 
#---------------------------------------------------------------------------------------------
import serial
import sys,time

SERIAL_TIMEOUT_CNT = 10
T_WATER_METER = 0x10
T_GAS_METER = 0x30
T_ELECTRI_METER = 0x40
C_READ_DATA = 0x01
C_READ_DATA_RESP = 0x81
C_RESET_BASE = 0x16
C_RESET_BASE_RESP = 0x96

C_READ_ADDR = 0x03
C_READ_ADDR_RESP = 0x83

C_SET_ADDR = 0x15
C_SET_ADDR_RESP = 0x95

debug_flag = 0

#-------------------------
# decode_cjt188
#    
# return: errcode,T,addr,C,data
#-------------------------
def decode_cjt188(data):
    #print 'decode_cjt188 hex_str:',data.encode('hex')
    if ord(data[0]) != 0x68:
        print 'decode_cjt188 fail 1'
        return -1,0,'',0,''
    
    # check len
    len_1 = len(data)
    if  len_1 < 13 or len_1 > 0x64:
        print 'decode_cjt188 fail 3'
        return -3,0,'',0,''

    len_2 = ord(data[10]) + 13
    if len_1 != len_2:
        print 'decode_cjt188 fail 4'    
        return -4,0,'',0,''
    
    # check tail 0x16
    if ord(data[len_2-1]) != 0x16:
        print 'decode_cjt188 fail 5'    
        return -5,0,'',0,''
    
    # check checksum
    cs = 0
    for i in xrange(0,len_2-2):
        #print hex(ord(data[i]))
        cs += ord(data[i])
        cs = cs % 256
        
    #print 'cs 1:',hex(cs)
    #cs = cs % 256
    #print 'caculate cs:',hex(cs)
    #print 'expected cs: ',data[len_2-2].encode('hex')
    
    if cs != ord(data[len_2-2]):
        print 'decode_cjt188 fail 6'    
        return -6,0,'',0,'' 
   
    # extract data (sub 0x33)
    if ord(data[10]) > 0:
        d_out = data[11:11+ord(data[10])]
    else:
        d_out = ''
      
    #      errcode,T,addr,C,data
    return 0,ord(data[1]),data[2:9],ord(data[9]),d_out

#-------------------------
# encode_cjt188
#------------------------- 
def encode_cjt188(t,addr,ctl,data):
    #print 'encode_cjt188:',str(t),str(addr),str(ctl),str(data)
    data_tag_2 = ''
    lens_data = len(data)
    #for i in xrange(0,lens_data):
    #    #data_tag_2 += chr(ord(data_tag[i])+0x33)
    #    data_tag_2 += chr(ord(data_tag[i]))
    
    if len(addr) != 7:
        return -1,''
        
    s1 = '\x68' + chr(t) + addr + chr(ctl) + chr(lens_data) + data

    # caculate cs
    cs = 0
    len_1 = len(s1)
    #print len_1
    for i in xrange(0,len_1):
        cs += ord(s1[i]) 
    cs = cs % 256
    s1 = s1 + chr(cs)
    # add tail
    s1 = s1 + '\x16'

    #print 'encode_cjt188 hex_str:',s1.encode('hex')
    return 0,s1
    
#-------------------------
# cjt188_get_addr
#-------------------------    
def cjt188_get_addr(serial):
    global debug_flag
    print 'cjt188_get_addr ...'
    try:
        #cmd2 = '\xfe\xfe\xfe\xfe\x68\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x03\x03\x81\x0a\x00\x49\x16'
        retcode,s1 = encode_cjt188(0xaa,'\xaa\xaa\xaa\xaa\xaa\xaa\xaa',C_READ_ADDR,'\x81\x0a\x00')
        if retcode < 0:
            return -2,''
        cmd2 = '\xfe\xfe\xfe' + s1
        #print 'cmd2:',cmd2.encode('hex')
        # for debug, please set debug_flag = 1
        #debug_flag = 0

        serial.write(cmd2)
        #time.sleep(0.5)
        resp = ''
        c = ''
        i = 0
        n = 0
        while i < SERIAL_TIMEOUT_CNT:
            c = serial.read(1024)
            if len(c) > 0:
                resp += c
                n = len(resp)
                if c[-1] == '\x16' and n >= 13:
                    break
            else:
                print '.'
                time.sleep(0.1)
                i += 1
        
        if i >= SERIAL_TIMEOUT_CNT:
            return -3,0

            
        #print 'resp:',resp.encode('hex')
        resp1 = cjt188_rm_fe(resp)
        
        
        ret,t,addr,ctl,data = decode_cjt188(resp1)
        if ret == 0 and ctl == C_READ_ADDR_RESP:
            print 'addr:',addr.encode('hex')
            return ret,addr
        else:
            return -1,''
        
    except Exception as e:
        print 'cjt188_get_addr exception!',str(e)
        return -1,''


#-------------------------
# cjt188_set_addr
#-------------------------    
def cjt188_set_addr(serial,new_addr):
    global debug_flag
    print 'cjt188_set_addr ...',new_addr.encode('hex')
    try:
        #cmd2 = '\xfe\xfe\xfe\xfe\x68\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x03\x03\x81\x0a\x00\x49\x16'
        retcode,s1 = encode_cjt188(0xaa,'\xaa\xaa\xaa\xaa\xaa\xaa\xaa',C_SET_ADDR,'\xa0\x18\x00' + new_addr)
        if retcode < 0:
            return -2,''
        cmd2 = '\xfe\xfe\xfe' + s1
        #print 'cmd2:',cmd2.encode('hex')
        # for debug, please set debug_flag = 1
        #debug_flag = 0
        if debug_flag != 1:
            serial.write(cmd2)
            #time.sleep(0.5)
            resp = ''
            c = ''
            i = 0
            n = 0
            while i < SERIAL_TIMEOUT_CNT:
                c = serial.read(1024)
                if len(c) > 0:
                    resp += c
                    n = len(resp)
                    if c[-1] == '\x16' and n >= 13:
                        break
                else:
                    #print '.'
                    time.sleep(0.1)
                    i += 1
            
            if i >= SERIAL_TIMEOUT_CNT:
                return -3,0
        else:
            resp = '\xfe\xfe\xfe\x68\x10\x12\x00\x00\x00\x00\x00\x00\x83\x03\x81\x0a\x00\x9b\x16'
        resp1 = cjt188_rm_fe(resp)
        #print 'resp1:',resp1
        
        ret,t,addr,ctl,data = decode_cjt188(resp1)
        if ret == 0 and ctl == C_SET_ADDR_RESP:
            print 'addr:',addr.encode('hex')
            return ret,addr
        else:
            return -1,''
        
    except Exception as e:
        print 'cjt188_set_addr exception!',str(e)
        return -1,''
        
#-------------------------
# cjt188_rm_fe
#-------------------------         
def cjt188_rm_fe(s):
    n = s.find('\x68')
    if n > 0:
        return s[n:]
    else:
        return ''
    
#-------------------------
# cjt188_read_data
# return: retcode,f1,f2,rt_se
# f1: flow_total ,unit 0.01 ton
# f2: flow_today ,unit 0.01 ton
#-------------------------    
def cjt188_read_data(serial,addr):
    global debug_flag
    print 'cjt188_read_data ...'
    try:
        #retcode,cmd2 = encode_cjt188(T_WATER_METER,addr,C_READ_DATA,'\x90\x1f\x00')
        retcode,cmd2 = encode_cjt188(T_WATER_METER,addr,C_READ_DATA,'\x1f\x90\x00')
        #retcode,cmd2 = encode_cjt188(T_WATER_METER,'\x12\x00\x00\x00\x00\x00\x00',C_READ_DATA,'\x90\x1f\x00')
        
        if retcode == -1:
            print 'cjt188_read_data debug 1'
            return -1,0,0,''
        cmd2 = '\xfe\xfe\xfe' + cmd2
        #print 'cmd2(hex):',cmd2.encode('hex')
        serial.write(cmd2)
        resp = ''
        c = ''
        i = 0
        
        n = 0
        while i < SERIAL_TIMEOUT_CNT:
            c = serial.read(1024)
            #print 'c:',c.encode('hex')
            if len(c) > 0:
                resp += c
                n = len(resp)
                if c[-1] == '\x16' and n >= 13:
                    break
            else:
                print '.'
                time.sleep(0.1)
                i += 1
                
            if i >= SERIAL_TIMEOUT_CNT:
                return -2,0,0,''
          
        resp1 = cjt188_rm_fe(resp)    
        retcode,t,addr,ctl,data = decode_cjt188(resp1)
        print '======================================='
        #print data.encode('hex')
        #print retcode,t,addr,ctl,data
        
        if retcode == 0 and t == T_WATER_METER and ctl == C_READ_DATA_RESP and len(data) == 0x16:
            print 'data:',data.encode('hex'),len(data)
            #i = ord(data[7])/16 *10000000
            #i += ord(data[7])%16 *1000000
            # 
            flow_total_s = data[3:7]
            flow_today_s = data[8:12]
            rt_s = data[13:13+7]
            print 'flow_total_s(hex):',flow_total_s.encode('hex')
            print 'flow_today_s(hex):',flow_today_s.encode('hex')
            f1  = ord(flow_total_s[3])/16 * 10000000
            f1 += ord(flow_total_s[3])%16 * 1000000
            f1 += ord(flow_total_s[2])/16 * 100000
            f1 += ord(flow_total_s[2])%16 * 10000
            f1 += ord(flow_total_s[1])/16 * 1000
            f1 += ord(flow_total_s[1])%16 * 100
            f1 += ord(flow_total_s[0])/16 * 10
            f1 += ord(flow_total_s[0])%16 * 1
            
            f2  = ord(flow_today_s[3])/16 * 10000000
            f2 += ord(flow_today_s[3])%16 * 1000000
            f2 += ord(flow_today_s[2])/16 * 100000
            f2 += ord(flow_today_s[2])%16 * 10000
            f2 += ord(flow_today_s[1])/16 * 1000
            f2 += ord(flow_today_s[1])%16 * 100
            f2 += ord(flow_today_s[0])/16 * 10
            f2 += ord(flow_today_s[0])%16 * 1
            
     
            return retcode,f1,f2,rt_s
            
        if retcode == 0 and t == T_WATER_METER and ctl == C_READ_DATA_RESP and len(data) == 0x9:
            print 'data:',data.encode('hex'),len(data)
            #i = ord(data[7])/16 *10000000
            #i += ord(data[7])%16 *1000000
            # 
            flow_total_s = data[3:7]
            rt_s = data[13:13+7]
            print 'flow_total_s(hex):',flow_total_s.encode('hex')
            f1  = ord(flow_total_s[3])/16 * 10000000
            f1 += ord(flow_total_s[3])%16 * 1000000
            f1 += ord(flow_total_s[2])/16 * 100000
            f1 += ord(flow_total_s[2])%16 * 10000
            f1 += ord(flow_total_s[1])/16 * 1000
            f1 += ord(flow_total_s[1])%16 * 100
            f1 += ord(flow_total_s[0])/16 * 10
            f1 += ord(flow_total_s[0])%16 * 1
            return retcode,f1,None,None
            
        else:
            print 'cjt188_read_data debug 2'        
            return -3,0,0,''
    except Exception as e:
        print 'cjt188_read_data exception!',str(e)
        return -4,0,0,''


    
#-------------------------
# main
#-------------------------
if __name__ == '__main__':

    # test basic functions
    try:
        serialport_path = sys.argv[1]
        serialport_baud = int(sys.argv[2])
        
        s = serial.Serial(serialport_path,serialport_baud,parity=serial.PARITY_EVEN,timeout=0.1)
        #print s
        
        # test cjt188_get_addr
        #print 'test cjt188_get_addr'
        #retcode,addr = cjt188_get_addr(s)
        #print retcode,addr
         
        #print 'step1. test encode_cjt188' 
        #retcode,s1 = encode_cjt188(T_WATER_METER,'\x12\x00\x00\x00\x00\x00\x00',C_READ_DATA,'\x90\x1f\x00')
        #if s1 == '\x68\x10\x12\x00\x00\x00\x00\x00\x00\x01\x03\x90\x1f\x00\x3d\x16':
        #    print 'encode_cjt188 passed'
        #else:
        #    print 'encode_cjt188 failed'
        #
        #print 'step2. test decode_cjt188'

        #s1 = '\xfe\xfe\xfe\x68\x10\x12\x00\x00\x00\x00\x00\x00\x81\x16\x90\x1f\x00\x10\x00\x10\x00\x2c'
        #s1 +='\x10\x00\x10\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x00\xff\x67\x16'
            
        #s2 = cjt188_rm_fe(s1)
        #retcode,t,addr,ctl,data = decode_cjt188(s2)
        #if retcode == 0 and addr == '\x12\x00\x00\x00\x00\x00\x00' and ctl == C_READ_DATA_RESP:
        #    print 'decode_cjt188 passed'
        #else:
        #    print 'decode_cjt188 failed'
    
    except Exception as e:
        print 'init serial error!',str(e)
        sys.exit(-1)
    

    # read meter addr
    print '-----------------------------'
    print 'get addr ...'
    while True:
        # get meter addr
        retcode,addr = cjt188_get_addr(s)
        #print retcode,addr
        if retcode < 0:
            print 'read addr fail! retry'
            time.sleep(1)
            
            continue
        else:
            print 'read addr ok! addr(hex):',addr.encode('hex')
            break
    
    #print '-----------------------------'
    #print 'set addr ...'
    # set meter addr
    #while True:
    #    # get meter addr
    #    #retcode,addr = cjt188_set_addr(s,'\x01\x26\x02\x16\x20\x00\x00')
    #    retcode,addr = cjt188_set_addr(s,'\x12\x00\x00\x00\x00\x00\x00')
    #    #print retcode,addr
    #    if retcode < 0:
    #        print 'set addr fail! retry'
    #        #time.sleep(0.1)
    #        continue
    #    else:
    #        print 'set addr ok! addr(hex):',addr.encode('hex')
    #        break
    
    print '-----------------------------------'
    print 'read data ...'
    time.sleep(1)
    while True:            

        retcode,f1,f2,rt_s = cjt188_read_data(s,addr)
        print 'cjt188_read_data result:',retcode,f1,f2,rt_s
        time.sleep(5)

    
    s.close()
