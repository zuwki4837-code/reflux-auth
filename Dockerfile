FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["RefluxAuth.csproj", "./"]
RUN dotnet restore "RefluxAuth.csproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "RefluxAuth.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "RefluxAuth.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
COPY --from=publish /app/publish .

# SQLite Database persistence volume recommendation
# We use /app/data for the database so it can be mounted as a persistent disk
RUN mkdir -p /app/data
ENV ASPNETCORE_URLS=http://+:8080

ENTRYPOINT ["dotnet", "RefluxAuth.dll"]
