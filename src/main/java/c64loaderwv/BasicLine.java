package c64loaderwv;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class BasicLine {
	static class TokenType
	{
		int id;
		String desc;
		TokenType(int i, String d)
		{
			id = i;
			desc = d;
		}
	}
	private static TokenType[] tokenList = { 
			new TokenType( 0x80, "END" ),
			new TokenType( 0x81, "FOR" ),
			new TokenType( 0x82, "NEXT" ),
			new TokenType( 0x83, "DATA" ),
			new TokenType( 0x84, "INPUT#" ),
			new TokenType( 0x85, "INPUT" ),
			new TokenType( 0x86, "DIM" ),
			new TokenType( 0x87, "READ" ),
			new TokenType( 0x88, "LET" ),
			new TokenType( 0x89, "GOTO" ),
			new TokenType( 0x8A, "RUN" ),
			new TokenType( 0x8B, "IF" ),
			new TokenType( 0x8C, "RESTORE"), 
			new TokenType( 0x8D, "GOSUB" ),
			new TokenType( 0x8E, "RETURN" ),
			new TokenType( 0x8F, "REM" ),
			new TokenType( 0x90, "STOP" ),
			new TokenType( 0x91, "ON" ),
			new TokenType( 0x92, "WAIT" ),
			new TokenType( 0x93, "LOAD" ),
			new TokenType( 0x94, "SAVE" ),
			new TokenType( 0x95, "VERIFY" ),
			new TokenType( 0x96, "DEF" ),
			new TokenType( 0x97, "POKE" ),
			new TokenType( 0x98, "PRINT#" ),
			new TokenType( 0x99, "PRINT" ),
			new TokenType( 0x9A, "CONT" ),
			new TokenType( 0x9B, "LIST" ),
			new TokenType( 0x9C, "CLR" ),
			new TokenType( 0x9D, "CMD" ),
			new TokenType( 0x9E, "SYS" ),
			new TokenType( 0x9F, "OPEN" ),
			new TokenType( 0xA0, "CLOSE" ),
			new TokenType( 0xA1, "GET" ),
			new TokenType( 0xA2, "NEW" ),
			new TokenType( 0xA3, "TAB(" ),
			new TokenType( 0xA4, "TO" ),
			new TokenType( 0xA5, "FN" ),
			new TokenType( 0xA6, "SPC(" ),
			new TokenType( 0xA7, "THEN" ),
			new TokenType( 0xA8, "NOT" ),
			new TokenType( 0xA9, "STEP" ),
			new TokenType( 0xAA, "+" ),
			new TokenType( 0xAB, "−" ),
			new TokenType( 0xAC, "*" ),
			new TokenType( 0xAD, "/" ),
			new TokenType( 0xAE, "^" ),
			new TokenType( 0xAF, "AND" ),
			new TokenType( 0xB0, "OR" ),
			new TokenType( 0xB1, ">" ),
			new TokenType( 0xB2, "=" ),
			new TokenType( 0xB3, "<" ),
			new TokenType( 0xB4, "SGN" ),
			new TokenType( 0xB5, "INT" ),
			new TokenType( 0xB6, "ABS" ),
			new TokenType( 0xB7, "USR" ),
			new TokenType( 0xB8, "FRE" ),
			new TokenType( 0xB9, "POS" ),
			new TokenType( 0xBA, "SQR" ),
			new TokenType( 0xBB, "RND" ),
			new TokenType( 0xBC, "LOG" ),
			new TokenType( 0xBD, "EXP" ),
			new TokenType( 0xBE, "COS" ),
			new TokenType( 0xBF, "SIN" ),
			new TokenType( 0xC0, "TAN" ),
			new TokenType( 0xC1, "ATN" ),
			new TokenType( 0xC2, "PEEK" ),
			new TokenType( 0xC3, "LEN" ),
			new TokenType( 0xC4, "STR$" ),
			new TokenType( 0xC5, "VAL" ),
			new TokenType( 0xC6, "ASC" ),
			new TokenType( 0xC7, "CHR$" ),
			new TokenType( 0xC8, "LEFT$" ),
			new TokenType( 0xC9, "RIGHT$" ),
			new TokenType( 0xCA, "MID$" ),
			new TokenType( 0xCB, "GO" ),
	    };
	public int linePos;
	public int nextLine;
	public int lineNumber;
	public int tokenSize;
	public String text;
	public BasicLine(BinaryReader br, int pos, int loadAddress) throws Exception
	{
		linePos = pos;
		int tpos = pos - loadAddress;
		nextLine = br.readShort(tpos) & 0xFFFF;
		lineNumber = br.readShort(tpos + 2) & 0xFFFF;
		text = "";
		ReadLine(br, tpos + 4);
	}
	
	private void ReadLine(BinaryReader br, int pos) throws Exception
	{
		tokenSize = 0;
		while(true)
		{
			byte b = br.readByte(pos++);
			tokenSize++;
			if(b > 0)
				text += (char)b;
			else if(b < 0)
				text += DecodeToken(b);
			else
				break;
		}
		text = text.trim();
	}
	
	private String DecodeToken(byte b)
	{
		String result = "[UNKNOWN TOKEN]";
		for(TokenType t : tokenList)
			if(t.id == (b & 0xFF))
			{
				result = " " + t.desc + " ";
				break;
			}
		return result;
	}
	
	public Structure getDataStructure()
	{
		Structure header_struct = new StructureDataType("L" + lineNumber, 0);
		header_struct.add(StructConverter.WORD,  0x02, "Next Line Address", null);
		header_struct.add(StructConverter.WORD,  0x02, "Line Number", null);
		header_struct.add(StructConverter.STRING, tokenSize, text, null);
		return header_struct;
	}
}
