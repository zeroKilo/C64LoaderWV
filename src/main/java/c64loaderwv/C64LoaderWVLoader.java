/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c64loaderwv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import org.python.jline.internal.Log;

import c64loaderwv.D64Image.D64Entry;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class C64LoaderWVLoader extends AbstractLibrarySupportLoader {

	public D64Image image;
	public int loadAddress = 0;
	private MemoryBlock block;
	@Override
	public String getName() {
		return "C64 Loader by Warranty Voider";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader br = new BinaryReader(provider, false);
		if(br.length() == 0x2AB00)
		{
			try
			{
				image = new D64Image(br);
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
			}
			catch(Exception ex) {
				Log.error(ex.getMessage());
			}
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader br = new BinaryReader(provider, true);
		int idx = -1;
		for(int i = 2; i < options.size(); i++)
			if((boolean)options.get(i).getValue()) {
				idx = i - 2;
				break;
			}
		if(idx == -1)
			throw new CancelledException();
		D64Entry e = image.entries.get(idx);
		long pos = D64Image.TPS2Raw(e.track, e.sector);
		try
		{
			byte[] buff = ReadFile(br, pos, e.nSectors, (boolean)options.get(0).getValue());
			ByteArrayProvider bap = new ByteArrayProvider(buff);
			int len = buff.length;
			if(loadAddress + len > 0x10000)
				len = 0x10000 - loadAddress;
			MakeBlock(program, "PROGRAM", e.name, loadAddress, bap.getInputStream(0), len, "111", log, monitor);
			if((boolean)options.get(1).getValue())
				DecodeBasicToken(new BinaryReader(bap, true), buff.length, program);
			bap.close();
		}
		catch(Exception ex) { 
			Log.error(ex.getMessage());
		}
	}
	
	public void DecodeBasicToken(BinaryReader br, int maxSize, Program program) throws Exception
	{
		int pos = loadAddress;
		ArrayList<BasicLine> lines = new ArrayList<BasicLine>();
		try
		{
			while(true)
			{
				BasicLine line = new BasicLine(br, pos, loadAddress);
				int t = line.nextLine - loadAddress;
				if(t < 0 || t >= maxSize)
					break;
				lines.add(line);
				if(t == 0)
					break;			
				pos = line.nextLine;
			}
		}
		catch(Exception ex) { }
		for(BasicLine line : lines)
		{
			Address addr = block.getStart();
			addr = addr.add(line.linePos - loadAddress);
			DataUtilities.createData(program, addr, line.getDataStructure(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
	}
		
	public byte[] ReadFile(BinaryReader br, long pos, long secCount, boolean defaultLoadAddress) throws Exception
	{
		ByteArrayOutputStream bop = new ByteArrayOutputStream();
		for(int i = 0; i < secCount; i++)
		{
			byte nextTrack = br.readByte(pos);
			byte nextSector = br.readByte(pos + 1);
			byte[] buff = null;
			if(i == 0)
			{
				if(defaultLoadAddress)
					loadAddress = 0x801;
				else
					loadAddress = br.readShort(pos + 2) & 0xFFFF;
				buff = br.readByteArray(pos + 4, 252);
			}
			else
				buff = br.readByteArray(pos + 2, 254);
			bop.write(buff);
			if(nextTrack <= 0 || nextSector < 0)
				break;
			pos = D64Image.TPS2Raw(nextTrack, nextSector);
		}
		return bop.toByteArray();		
	}
	
	public void MakeBlock(Program program, String name, String desc, long address, InputStream s, int size, String flags, MessageLog log, TaskMonitor monitor)
	{
		try
		{
			byte[] bf = flags.getBytes();
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			block = MemoryBlockUtils.createInitializedBlock(program, false, name, addr, s, size, desc, null, bf[0] == '1', bf[1] == '1', bf[2] == '1', log, monitor);			
		}
		catch (AddressOverflowException e) {
			Msg.error(this, e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		list.add(new Option("Use default (0x801) loading address?", false));
		list.add(new Option("Try decode basic tokens?", true));
		int count = 0;
		for(D64Entry entry : image.entries)
			list.add(new Option("Load Program \"" + entry.name + "\"", count++ == 0));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		int count = 0;
		for(Option o : options)
			if((boolean)o.getValue())
				count++;
		if((boolean)options.get(0).getValue())
			count--;
		if((boolean)options.get(1).getValue())
			count--;
		return count < 2 ? null : "Please select only one program to load!";
	}
}
