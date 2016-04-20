using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using IpLab.Core;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using System.IO;

namespace IpLab
{

	public class ViewModel : INotifyPropertyChanged
	{
		private ObservableCollection<IPPacket> _filteredPackets = new ObservableCollection<IPPacket>();
		public ObservableCollection<IPPacket> FilteredPackets
		{
			get { return _filteredPackets; }
			set
			{
				_filteredPackets = value;
				OnPropertyChanged();
			}
		}
		private IPPacket _selectedPacket;
		public IPPacket SelectedPacket { get { return _selectedPacket; } set { _selectedPacket = value; OnPropertyChanged(); } }
		public List<IPPacket> Packets { get; set; } = new List<IPPacket>();

		private NetworkSniffer _sniffer = new NetworkSniffer(new IPEndPoint(IPAddress.Broadcast, 0));


		public event PropertyChangedEventHandler PropertyChanged;
		protected void OnPropertyChanged([CallerMemberName] string propertyName = null) =>
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

		private string _destinationFilter = "";
		private string _sourceFilter = "";
		private string _protocolFilter = "";


		public async Task StartSniff()
		{
			while (true)
			{
				var p = await _sniffer.SniffAsync();
				Packets.Add(p);
				if (p.Destination.Contains(_destinationFilter) && p.Source.Contains(_sourceFilter) && p.Protocol.ToString().Contains(_protocolFilter))
					FilteredPackets.Add(p);
			}
		}


		public void FilterPackets(string filterText)
		{
			var filters = filterText.Split(',', ';').ToList();
			_destinationFilter = _sourceFilter = _protocolFilter = string.Empty;
			foreach (var filter in filters)
			{
				if (filter.Contains("dest:"))
					_destinationFilter = new string(filter.Skip(filter.IndexOf(':') + 1).ToArray());
				if (filter.Contains("source:"))
					_sourceFilter = new string(filter.Skip(filter.IndexOf(':') + 1).ToArray());
				if (filter.Contains("protocol:"))
					_protocolFilter = new string(filter.Skip(filter.IndexOf(':') + 1).ToArray());
			}

			FilteredPackets.Clear();
			foreach (var p in Packets)
				if (p.Destination.Contains(_destinationFilter) && p.Source.Contains(_sourceFilter) && p.Protocol.ToString().Contains(_protocolFilter))
					FilteredPackets.Add(p);
		}

	}

	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		ViewModel _vm = new ViewModel();

		public MainWindow()
		{
			InitializeComponent();
			this.Loaded += WindowLoaded;
		}

		private async void WindowLoaded(object sender, RoutedEventArgs e)
		{
			DataContext = _vm;
			await _vm.StartSniff();
		}

		private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
		{
			var filterText = (sender as TextBox)?.Text ?? "";
			_vm.FilterPackets(filterText);
		}

		private void ClearButtonClick(object sender, RoutedEventArgs e)
		{
			_vm.Packets.Clear();
			_vm.FilteredPackets.Clear();
		}

		private void SaveButtonClick(object sender, RoutedEventArgs e)
		{
			SaveFileDialog dialog = new SaveFileDialog() { Filter = "Text documents (.txt)|*.txt", DefaultExt = ".text", FileName = "payload"};
			bool? result = dialog.ShowDialog();
			if(result.GetValueOrDefault() && _vm.SelectedPacket != null)
				File.WriteAllText(dialog.FileName, _vm.SelectedPacket.Payload);
		}
	}
}
