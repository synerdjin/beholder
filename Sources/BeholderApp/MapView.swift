import BeholderCore
import MapKit
import SwiftUI

/// Where the far ends of current connections are.
///
/// Locations come from a local database; nothing is asked of the network. A tool for
/// watching what your machine talks to has no business querying a geolocation API,
/// because the query would leak precisely the information it exists to show you.
struct ConnectionMapView: View {
    let snapshot: FlowSnapshot

    /// One pin per place rather than per connection: a dozen connections to the same
    /// datacentre are one dot on a map, and stacking them would just hide each other.
    private var places: [Place] {
        var byCoordinate: [String: [WireFlow]] = [:]
        for flow in snapshot.flows {
            guard let location = flow.location,
                let latitude = location.latitude,
                let longitude = location.longitude
            else { continue }
            // Rounded so endpoints in the same city group together instead of forming a
            // cloud of near-identical pins.
            let key = String(format: "%.1f,%.1f", latitude, longitude)
            byCoordinate[key, default: []].append(flow)
        }

        return byCoordinate.compactMap { key, flows -> Place? in
            guard let first = flows.first, let location = first.location,
                let latitude = location.latitude, let longitude = location.longitude
            else { return nil }
            return Place(
                id: key,
                coordinate: CLLocationCoordinate2D(latitude: latitude, longitude: longitude),
                label: location.description,
                flows: flows.sorted { $0.totalBytes > $1.totalBytes }
            )
        }
        .sorted { $0.totalBytes > $1.totalBytes }
    }

    private var placedCount: Int {
        snapshot.flows.filter { $0.location?.hasCoordinates == true }.count
    }

    var body: some View {
        if places.isEmpty {
            ContentUnavailableView {
                Label("No locations yet", systemImage: "globe")
            } description: {
                Text(
                    snapshot.flows.isEmpty
                        ? "Waiting for connections."
                        : "No connection could be placed. Install the geolocation "
                            + "database with `make geoip`, then restart the daemon."
                )
            }
        } else {
            Map {
                ForEach(places) { place in
                    Annotation(place.label, coordinate: place.coordinate) {
                        PlaceMarker(place: place)
                    }
                }
            }
            .mapStyle(.standard(elevation: .flat))
            .overlay(alignment: .bottomLeading) {
                // Says plainly how much of the picture is on the map. A map showing 40 of
                // 200 connections without saying so implies the other 160 do not exist.
                Text(
                    "\(placedCount) of \(snapshot.flows.count) connections placed · "
                        + "\(places.count) locations"
                )
                .font(.caption)
                .padding(6)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 6))
                .padding(10)
            }
        }
    }
}

fileprivate struct Place: Identifiable {
    let id: String
    let coordinate: CLLocationCoordinate2D
    let label: String
    let flows: [WireFlow]
    var totalBytes: UInt64 { flows.reduce(0) { $0 + $1.totalBytes } }
}

/// A dot sized by traffic volume, so the map shows where the bytes go rather than merely
/// where connections exist.
private struct PlaceMarker: View {
    let place: Place
    @State private var isShowingDetail = false

    private var diameter: CGFloat {
        // Logarithmic: a 100 MB transfer is worth a bigger dot than a 1 KB one, but not
        // one a hundred thousand times the area.
        let magnitude = log10(Double(max(place.totalBytes, 1)))
        return min(max(8, magnitude * 3.2), 30)
    }

    var body: some View {
        Circle()
            .fill(.orange.opacity(0.75))
            .stroke(.orange, lineWidth: 1.5)
            .frame(width: diameter, height: diameter)
            .onTapGesture { isShowingDetail.toggle() }
            .popover(isPresented: $isShowingDetail) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(place.label).font(.headline)
                    Text(
                        "\(pluralised(place.flows.count, "connection")) · "
                            + formatBytes(Double(place.totalBytes))
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    Divider()
                    ForEach(place.flows.prefix(8)) { flow in
                        HStack(spacing: 6) {
                            Text(flow.processName ?? "unknown")
                                .fontWeight(.medium)
                            Text(flow.remoteDescription)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        .font(.caption)
                    }
                    if place.flows.count > 8 {
                        Text("… and \(place.flows.count - 8) more")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(12)
                .frame(minWidth: 260)
            }
    }
}
