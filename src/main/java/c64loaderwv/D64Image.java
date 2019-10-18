package c64loaderwv;

import java.util.ArrayList;
import ghidra.app.util.bin.BinaryReader;

public class D64Image {
	
	public class D64Entry
	{
		public byte type;
		public byte track;
		public byte sector;
		public String name;
		public int nSectors;
		
		public D64Entry(BinaryReader br, long pos) throws Exception
		{
			type = br.readByte(pos);
			track = br.readByte(pos + 1);
			sector = br.readByte(pos + 2);
			name = ReadC64String(br, pos + 3, 16);
			nSectors = br.readByte(pos + 0x1C) + br.readByte(pos + 0x1D) * 0x100;
		}
	}
	
	public String DiskName;
	public String DiskId;
	public ArrayList<D64Entry> entries = new ArrayList<D64Image.D64Entry>();
	
	public D64Image(BinaryReader br) throws Exception
	{
		DiskName = ReadC64String(br, 0x16590, 16);
		DiskId = ReadC64String(br, 0x165A2, 5);
		ReadBlock(br, 0x16600);
	}
	
	private String ReadC64String(BinaryReader br, long pos, int len) throws Exception
	{
		return br.readAsciiString(pos, len).replace((char)0xA0, ' ').trim();
	}
	
	private void ReadBlock(BinaryReader br, long pos) throws Exception
	{
		byte nextTrack = br.readByte(pos);
		byte nextSector = br.readByte(pos + 1);
		for(int i = 0; i < 8; i++)
		{			
			D64Entry entry = new D64Entry(br, pos + i * 32 + 2);
			if((entry.type & 0x7) == 2)
				entries.add(entry);
		}
		if(nextTrack > 0 && nextSector >= 0)
			ReadBlock(br, TPS2Raw(nextTrack, nextSector));
	}
	
	public static long TPS2Raw(byte track, byte sector)
	{
		int sectorOffset = sector;
		for(int i = 1; i < track; i++)
		{
			if(i <= 17) sectorOffset += 21;
			if(i >= 18 && i <= 24) sectorOffset += 19;
			if(i >= 25 && i <= 30) sectorOffset += 18;
			if(i >= 31) sectorOffset += 17;
		}
		return sectorOffset * 0x100;
	}
}
