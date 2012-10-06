using System;

public struct SharedData
{
    public long xi;
    public long yi;
};

public class ShamirSS
{
    // number of participants
    public uint numAllParts;
    // number of participants needed for recovery
    public uint numNecessaryParts;
    // prime p for the field to work in
    public BigInteger modP;

    

    public ShamirSS(uint _numAllParts, uint _numNecessaryParts, long _modP)
    {
        numAllParts = _numAllParts;
        numNecessaryParts = _numNecessaryParts;
        modP = _modP;

        //find the next prime larger than secret
        bool found = false;
        while (!found)
        {
            if (modP.FermatLittleTest(5))
                found = true;
            else
                modP++;
        }


    }
    // secret shares an input based on n,r parameters
    public SharedData[] ShareData( long secret)
    {

        BigInteger[] coefficients = new BigInteger[numNecessaryParts - 1];
        BigInteger[] toReturn_p = new BigInteger[numAllParts];

        for (int i = 0; i < numNecessaryParts - 1; i++)
        {
            BigInteger a = new BigInteger();
            a.genRandomBits(64, new Random());
            a = a.abs() % modP;
            coefficients[i] = a;

        }

        for (long i = 0; i < numAllParts; i++)
        {
            toReturn_p[i] = 0;

            for (long j = 0; j < numNecessaryParts - 1; j++)
            {

                BigInteger tmp = new BigInteger((long)(Math.Pow(i + 1, j + 1)));

                toReturn_p[i] = (toReturn_p[i] + (BigInteger)(coefficients[j] * tmp)) % modP;
            }

        }

        SharedData[] toReturn = new SharedData[numAllParts];

        for (int i = 0; i < numAllParts; i++)
        {
            toReturn_p[i] = (toReturn_p[i] + new BigInteger(secret)) % modP;
            toReturn[i].yi = toReturn_p[i].LongValue();
            toReturn[i].xi = i + 1;
        }

        return toReturn;
    }

    public long ReconstructData(SharedData[] shares)
    {

        BigInteger[] nominators = new BigInteger[numNecessaryParts];

        for (int i = 0; i < numNecessaryParts; i++)
        {
            nominators[i] = 1;

            for (int j = 0; j < numNecessaryParts; j++)
            {
                if (i != j)
                {
                    BigInteger inv = new BigInteger(shares[i].xi) - new BigInteger(shares[j].xi);
                    inv = inv % modP;
                    if (inv < 0)
                    {
                        while (inv <= 0)
                            inv += modP;
                        inv = inv.modInverse(modP);
                    }
                    else if (inv != 1)
                    {
                        inv = inv.modInverse(modP);
                    }

                    nominators[i] = (nominators[i] * (new BigInteger(shares[j].xi) * inv)) % modP;
                }
            }

        }

        for (int i = 0; i < numNecessaryParts; i++)
        {
            nominators[i] = (nominators[i] * new BigInteger(shares[i].yi)) % modP;
        }

        BigInteger nominator = new BigInteger(0);

        for (int i = 0; i < numNecessaryParts; i++)
        {
            nominator = (nominator + nominators[i]) % modP;
        }

        return nominator.LongValue();
    }
}
