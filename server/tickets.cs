using System;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using System.Windows.Forms;


public class mytickets
{
    public struct ticket
    {
        public byte[] origFirst;
        public byte[] signFirst;

        public byte[] origSecond;
        public byte[] signSecond;

        public ticket(byte[] a, byte[] b, byte[] c, byte[] d)
        {
            origFirst = a;
            signFirst = b;
            origSecond = c;
            signSecond = d;

        }
    };

    public List<ticket> ticketlist;

    public mytickets()
    {
        ticketlist = new List<ticket>();

    }

    public string EncodeToString()
    {
        string encodedStr = "";
        for (int i = 0; i < ticketlist.Count; i++)
        {
            encodedStr += BytesToHex(ticketlist[i].origFirst).Replace(" ", "") + "," + BytesToHex(ticketlist[i].signFirst).Replace(" ", "") + ","
                        + BytesToHex(ticketlist[i].origSecond).Replace(" ", "") + "," + BytesToHex(ticketlist[i].signSecond).Replace(" ", "") + ";";
        }
        return encodedStr;
    }

    public void DecodeFromString(string ticketString)
    {
        string[] recvTickets;
        recvTickets = ticketString.Split(';');
        string[] recvFields;
        for (int i = 0; i < recvTickets.Length - 1; i++)//todo
        {
            recvFields = recvTickets[i].Split(',');
            if (recvFields.Length != 4)
                MessageBox.Show("missing ticket field");
            else
            {
                ticket myticket = new ticket(HexToBytes(recvFields[0]), HexToBytes(recvFields[1]), HexToBytes(recvFields[2]), HexToBytes(recvFields[3]));
                ticketlist.Add(myticket);
            }
        }


    }

    public string ExportSingleTicket(int i)
    {
        string encodedStr = "";
        encodedStr += BytesToHex(ticketlist[i].origFirst).Replace(" ", "") + "," + BytesToHex(ticketlist[i].signFirst).Replace(" ", "") + ","
                        + BytesToHex(ticketlist[i].origSecond).Replace(" ", "") + "," + BytesToHex(ticketlist[i].signSecond).Replace(" ", "")+";";

        return encodedStr;

    }

    public void AddToList(byte[] senderIDdata, byte[] senderIDsign, byte[] receiverIDdata, byte[] receiverIDsign)
    {
        ticket myticket = new ticket(senderIDdata, senderIDsign, receiverIDdata, receiverIDsign);
        ticketlist.Add(myticket);

    }
    public void AddToList(ticket _ticket)
    {
        ticketlist.Add(_ticket);

    }
    private static string BytesToHex(byte[] bytes)
    {
        StringBuilder hexString = new StringBuilder(bytes.Length);
        for (int i = 0; i < bytes.Length; i++)
        {
            hexString.Append(bytes[i].ToString("X2") + " ");
        }

        return hexString.ToString().TrimEnd();
    }
    private static byte[] HexToBytes(String HexString)
    {

        int NumberChars = HexString.Length;
        byte[] bytes = new byte[NumberChars / 2];
        for (int i = 0; i < NumberChars; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
        }
        return bytes;
    }

    public int GetClientCount()
    {
        return ticketlist.Count;

    }



}

