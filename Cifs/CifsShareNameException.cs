namespace Cifs
{
    using System;

    /// <summary>
    ///    Summary description for CifsShareNameException.
    /// </summary>
    public class CifsShareNameException: CifsIoException
    {
        public CifsShareNameException(string key): base(key)
        {
        }

		public CifsShareNameException(string key, object i1): base(key, i1)
		{
		}

		public CifsShareNameException(string key, object i1, object i2): base(key, i1, i2)
		{
		}

    } // class CifsShareNameException
} // namespace Cifs
