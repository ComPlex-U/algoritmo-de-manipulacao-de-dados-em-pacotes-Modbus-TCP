package com.cic;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;
import java.time.Instant;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;

	
public class App {
	public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_RED_BACKGROUND = "\u001B[41m";
	public static void main(String[] args) throws IOException, PcapNativeException, NotOpenException
	{
		String intro ="";
		String inputFile = "";
		Scanner command = new Scanner (System.in);

		System.out.println(ANSI_RED_BACKGROUND
                           + "Manipulador de IP e MAC Modbus/tcp"
                           + ANSI_RESET);

		System.out.println("Indique o ficheiro a ser lido:");
		inputFile = command.nextLine();
		
		command.close();
		
		PcapHandle fileHandle = openfile(inputFile);
		readpacket(fileHandle);
		
	}
	public static PcapHandle openfile(String filename) throws PcapNativeException
	{
		final String PCAP_FILE_KEY = App.class.getName() + ".pcapFile";
		final String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, filename);
		
		PcapHandle handle;
		
		try
		{
			handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
		}
		catch (PcapNativeException e)
		{
			handle = Pcaps.openOffline(PCAP_FILE);
		}
		return handle;
	}
	public static void readpacket(PcapHandle newHandle) throws PcapNativeException, NotOpenException, IOException
	{
		PcapHandle handle = newHandle;
		
		String srcIP = "192.168.1.1";
		String dstIP = "192.168.2.1";
		String srcMAC = "00:0d:29:12:54:ac";
		String dstMAC = "00:0d:29:3f:e6:cd";
	
		File results = new File ("results.pcap");
		PcapDumper dumper = handle.dumpOpen(results.getAbsolutePath());
		
		for(int i = 0; i<1; i ++)
		{
			try
			{
				Packet packet = handle.getNextPacketEx();
				
				//Frame
				Instant originalTimestamp = ((PcapPacket) packet).getTimestamp();
				System.out.println(originalTimestamp);
				
				//Ethernet
				MacAddress originalDestMAC = (packet.get(EthernetPacket.class).getHeader()).getDstAddr();
				System.out.println(originalDestMAC);
				MacAddress originalSrcMAC = (packet.get(EthernetPacket.class).getHeader()).getSrcAddr();
				System.out.println(originalSrcMAC);
				EtherType originalType = (packet.get(EthernetPacket.class).getHeader()).getType();
				System.out.println(originalType);
				
				//IPv4
				IpVersion originalVersion = (packet.get(IpV4Packet.class).getHeader()).getVersion();
				System.out.println(originalVersion);
				byte originalIHL = (packet.get(IpV4Packet.class).getHeader()).getIhl();
				System.out.println(originalIHL);
				IpV4Tos originalTOS = (packet.get(IpV4Packet.class).getHeader()).getTos();
				System.out.println(originalTOS);
				short originalTotalLength = (packet.get(IpV4Packet.class).getHeader()).getTotalLength();
				System.out.println(originalTotalLength);
				short originalIdentification = (packet.get(IpV4Packet.class).getHeader()).getIdentification();
				System.out.println(originalIdentification);
				short originalFragmentationOffset = (packet.get(IpV4Packet.class).getHeader()).getFragmentOffset();
				System.out.println(originalFragmentationOffset);
				byte originalTTL = (packet.get(IpV4Packet.class).getHeader()).getTtl();
				System.out.println(originalTTL);
				IpNumber originalProtocol = (packet.get(IpV4Packet.class).getHeader()).getProtocol();
				System.out.println(originalProtocol);
				short originalHeaderChecksum = (packet.get(IpV4Packet.class).getHeader()).getHeaderChecksum();
				System.out.println(originalHeaderChecksum);
				Inet4Address originalSrcIP = (packet.get(IpV4Packet.class).getHeader()).getSrcAddr();
				System.out.println(originalSrcIP);
				Inet4Address originalDestIP = (packet.get(IpV4Packet.class).getHeader()).getDstAddr();
				System.out.println(originalDestIP);
				
				//TCP
				TcpPort originalSrcPort = (packet.get(TcpPacket.class).getHeader()).getSrcPort();
				System.out.println(originalSrcPort);
				TcpPort originalDestPort = (packet.get(TcpPacket.class).getHeader()).getDstPort();
				System.out.println(originalDestPort);
				int originalSeqNumber = (packet.get(TcpPacket.class).getHeader()).getSequenceNumber();
				System.out.println(originalSeqNumber);
				int originalAckNumber = (packet.get(TcpPacket.class).getHeader()).getAcknowledgmentNumber();
				System.out.println(originalAckNumber);
				byte originalDataOffset = (packet.get(TcpPacket.class).getHeader()).getDataOffset();
				System.out.println(originalDataOffset);
				byte originalReserved = (packet.get(TcpPacket.class).getHeader()).getReserved();
				System.out.println(originalReserved);
				boolean originalURG = (packet.get(TcpPacket.class).getHeader()).getUrg();
				System.out.println(originalURG);
				boolean originalACK = (packet.get(TcpPacket.class).getHeader()).getAck();
				System.out.println(originalACK);
				boolean originalRST = (packet.get(TcpPacket.class).getHeader()).getRst();
				System.out.println(originalRST);
				boolean originalSYN = (packet.get(TcpPacket.class).getHeader()).getSyn();
				System.out.println(originalSYN);
				boolean originalFIN = (packet.get(TcpPacket.class).getHeader()).getFin();
				System.out.println(originalFIN);
				short originalWindow = (packet.get(TcpPacket.class).getHeader()).getWindow();
				System.out.println(originalWindow);
				short originalChecksum = (packet.get(TcpPacket.class).getHeader()).getChecksum();
				System.out.println(originalChecksum);
				short originalUrgPointer = (packet.get(TcpPacket.class).getHeader()).getUrgentPointer();
				System.out.println(originalUrgPointer);
				
				//Modbus/TCP
				Packet modbus = packet.get(TcpPacket.class).getPayload();
				int size = packet.get(TcpPacket.class).getPayload().length() - 9;
				System.out.println(modbus);
				byte [] data = modbus.getRawData();
				byte min = 5;
				byte max = 30;
				for( i = 0; i < size; i++)
				{
					data[i+9] = (byte)(Math.random()*(max-min+1)+min);
				}
				System.out.println(data);
				System.out.println(data[6]);
				
				//Criar novo pacote
				UnknownPacket.Builder modbusTCP = buildModbusTCP(data);
				TcpPacket.Builder tcp = buildTCP(originalSrcPort, originalDestPort, originalSeqNumber, originalAckNumber, originalDataOffset, originalReserved, originalURG, originalACK, originalRST, originalSYN, originalFIN, originalWindow, originalChecksum, originalUrgPointer, modbusTCP);
				IpV4Packet.Builder ipv4 = buildIPv4(originalVersion, originalIHL, originalTOS, originalTotalLength, originalIdentification, originalFragmentationOffset, originalTTL, originalProtocol, originalHeaderChecksum, (Inet4Address) Inet4Address.getByName(srcIP),Inet4Address.getByName(dstIP),tcp);
				EthernetPacket ethernet = buildEthernet((MacAddress) MacAddress.getByName(dstMAC), (MacAddress) MacAddress.getByName(srcMAC),originalType, ipv4);
				
				dumper.dump(ethernet, originalTimestamp);
				
				String[] parts = srcIP.split("\\.");
				int oct3 = Integer.parseInt(parts[2]);
				int oct4 = Integer.parseInt(parts[3]);
				oct4++;
				if(oct4 >= 254)
				{
					oct4 = 0;
					oct3++;
				}
				srcIP = parts[0] + "." + parts[1] + "." + Integer.toString(oct3) + "." + Integer.toString(oct4);
				
			}
			catch (TimeoutException e) {}
			catch (EOFException e)
			{
				System.out.println("EOF");
				break;
			}
			
		}
		handle.close();
		dumper.close();
	}
	public static UnknownPacket.Builder buildModbusTCP(byte[] data)
	{
		UnknownPacket.Builder modbusTCP = new UnknownPacket.Builder().rawData(data);
		return modbusTCP;
	}
	public static TcpPacket.Builder buildTCP(TcpPort srcPort, TcpPort destPort, int seqNumber, int acknNumber, byte dataOffset, byte reserved, boolean urg, boolean ack, boolean rst, boolean syn, boolean fin, short window, short checksum, short urgPointer, UnknownPacket.Builder payload)
	{
		TcpPacket.Builder tcp = new TcpPacket.Builder()
				.srcPort(srcPort)
				.dstPort(destPort)
				.sequenceNumber(seqNumber)
				.acknowledgmentNumber(acknNumber)
				.dataOffset(dataOffset)
				.reserved(reserved)
				.urg(urg)
				.ack(ack)
				.rst(rst)
				.syn(syn)
				.fin(fin)
				.window(window)
				.checksum(checksum)
				.urgentPointer(urgPointer)
				.payloadBuilder(payload);
		return tcp;
	}
	public static IpV4Packet.Builder buildIPv4(IpVersion version, byte ihl, IpV4Tos tos, short totalLength, short identification, short fragmentOffset, byte ttl, IpNumber protocol, short headerChecksum, Inet4Address srcIP, InetAddress inetAddress, TcpPacket.Builder payload)
	{
		IpV4Packet.Builder ipv4 = new IpV4Packet.Builder()
        		.version(version)
        		.ihl(ihl)
        		.tos(tos)
        		.totalLength(totalLength)
        		.identification(identification)
        		.fragmentOffset(fragmentOffset)
                .ttl(ttl)
                .protocol(protocol)
                .headerChecksum(headerChecksum)
                .srcAddr(srcIP)
                .dstAddr((Inet4Address) inetAddress)
                .payloadBuilder(payload);
		return ipv4;
	}
	public static EthernetPacket buildEthernet(MacAddress destMAC, MacAddress srcMAC, EtherType type, IpV4Packet.Builder payload)
	{
		EthernetPacket ethernet = new EthernetPacket.Builder()
				.dstAddr(destMAC)
				.srcAddr(srcMAC)
				.type(type)
				.payloadBuilder(payload)
				.paddingAtBuild(true)
				.build();
		return ethernet;
	}
}

